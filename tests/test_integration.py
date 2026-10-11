"""Opt-in checks against actual Java/Android tools and a compiled APK fixture."""
import json
import os
import secrets
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from uat import apk, binary, external, project, recipes, signing
from uat.common import ToolError, sha256

AVAILABLE = os.environ.get("UAT_INTEGRATION_APK") and all(shutil.which(x) for x in ("apktool", "apksigner", "zipalign", "keytool", "jadx"))


@unittest.skipUnless(AVAILABLE, "Set UAT_INTEGRATION_APK and install external tools for integration checks")
class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.input = Path(os.environ["UAT_INTEGRATION_APK"])

    def tearDown(self):
        self.temp.cleanup()

    def test_decode_recipe_build_sign_verify(self):
        original_hash = sha256(self.input)
        workspace = self.root / "project"
        project.create(self.input, workspace)
        project.decode(workspace)
        recipe = self.root / "edit.json"
        recipe.write_text(json.dumps({"version": 1, "changes": [{
            "path": "decoded/AndroidManifest.xml", "kind": "xml_set_attribute", "xpath": "./application",
            "attribute": "android:allowBackup", "expected": "true", "value": "false", "expected_matches": 1,
        }]}))
        changed = self.root / "modified-project"
        recipes.apply(recipe, workspace, changed)
        key = self.root / "key.p12"
        signed = self.root / "signed.apk"
        with patch.dict(os.environ, {"UAT_TEST_PASS": secrets.token_urlsafe(24)}):
            signing.create_key(key, password_env="UAT_TEST_PASS")
            result = project.rebuild(changed, signed, key, password_env="UAT_TEST_PASS")
            self.assertIn("Verified using v2 scheme", result["verification"])
            self.assertIn("Verified using v3 scheme", result["verification"])
            self.assertIn("Signer #1 certificate SHA-256 digest", signing.verify(signed))
            self.assertIn("SHA256", signing.key_info(key, "UAT_TEST_PASS"))
            signing_input = self.root / "set-input"
            signing_input.mkdir()
            shutil.copyfile(self.input, signing_input / "base.apk")
            shutil.copyfile(self.input, signing_input / "second.apk")
            batch = signing.sign_set(signing_input, self.root / "set-signed", key, password_env="UAT_TEST_PASS")
            self.assertEqual(len(batch["apks"]), 2)
            self.assertTrue(all("Verified using v2 scheme" in item["verification"] for item in batch["apks"]))
        self.assertEqual(apk.inspect(signed)["manifest"]["application"]["allowBackup"], "false")
        self.assertEqual(sha256(self.input), original_hash)
        self.assertEqual(project.load(changed)[1]["history"][-1]["signed"], True)
        self.assertIn("AndroidManifest.xml", apk.compare(self.input, signed)["changed"])
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        rebuilt_dex = self.root / "rebuilt-dex"
        apk.extract(signed, rebuilt_dex, "classes*.dex")
        integrity = binary.dex_info(next(rebuilt_dex.glob("classes*.dex")))
        self.assertTrue(integrity["sha1_valid"])
        self.assertTrue(integrity["adler32_valid"])
        with patch.dict(os.environ, {"UAT_TEST_PASS": "incorrect-password"}):
            with self.assertRaises(ToolError):
                signing.sign(self.input, self.root / "failed.apk", key, password_env="UAT_TEST_PASS")
        self.assertFalse((self.root / "failed.apk").exists())
        with self.assertRaises(ToolError):
            signing.verify(self.input)

    def test_jadx_and_dex(self):
        dest = self.root / "java"
        external.decompile(self.input, dest)
        self.assertTrue(list(dest.rglob("*.java")))
        extracted = self.root / "dex"
        apk.extract(self.input, extracted, "classes*.dex")
        report = binary.dex_info(next(extracted.glob("classes*.dex")))
        self.assertTrue(report["adler32_valid"])
        self.assertGreater(report["class_count"], 0)


if __name__ == "__main__":
    unittest.main()
