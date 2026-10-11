import hashlib
import json
import mmap
import os
import stat
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from uat import analysis, apk, binary, project, recipes, search
from uat.axml import parse_manifest, manifest_summary
from uat.common import ToolError, sha256
from uat.proc_helper import dump, parse_maps

MANIFEST = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example.demo" android:versionName="1"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><application android:allowBackup="true"><activity android:name=".Main" android:exported="false"/></application></manifest>'''


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.apk = self.root / "sample.apk"
        with zipfile.ZipFile(self.apk, "w") as z:
            z.writestr("AndroidManifest.xml", MANIFEST)
            z.writestr("assets/config.txt", "https://example.org\nenabled=true\n")
            z.writestr("lib/arm64-v8a/libil2cpp.so", b"\x00Java_org_example_Native_test\x00il2cpp_domain_get\x00")
            z.writestr("META-INF/CERT.SF", "obsolete signature")

    def tearDown(self):
        self.temp.cleanup()

    def recipe(self, rules):
        path = self.root / "recipe.json"
        path.write_text(json.dumps({"version": 1, "changes": rules}))
        return path

    def test_inspect_manifest_engine_abi(self):
        report = apk.inspect(self.apk, True)
        self.assertEqual(report["manifest"]["package"], "org.example.demo")
        self.assertEqual(report["manifest"]["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(report["manifest"]["components"][0]["exported_declared"], "false")
        self.assertEqual(report["abis"], ["arm64-v8a"])
        self.assertEqual(report["engine_hints"], ["Unity IL2CPP"])
        self.assertEqual(report["entry_hashes"]["AndroidManifest.xml"], hashlib.sha256(MANIFEST).hexdigest())

    def test_automatic_analysis_reports(self):
        output = self.root / "analysis"
        result = analysis.analyze(self.apk, output)
        report = json.loads((output / "analysis.json").read_text())
        self.assertEqual(report["manifest"]["package"], "org.example.demo")
        self.assertGreater(result["search_hits"]["endpoints"], 0)
        self.assertTrue((output / "extracted/assets/config.txt").is_file())

    def test_extract_glob_and_no_overwrite(self):
        dest = self.root / "out"
        apk.extract(self.apk, dest, "assets/*")
        self.assertTrue((dest / "assets/config.txt").is_file())
        self.assertFalse((dest / "AndroidManifest.xml").exists())
        with self.assertRaises(ToolError):
            apk.extract(self.apk, dest)

    def test_zip_traversal_and_windows_paths(self):
        for index, name in enumerate(["../escape", "/absolute", "a/../../escape", "a\\evil", "C:/evil", "a/./evil"]):
            malicious = self.root / f"bad{index}.apk"
            with zipfile.ZipFile(malicious, "w") as z:
                z.writestr(name, "payload")
            with self.assertRaises(ToolError):
                apk.extract(malicious, self.root / f"extract{index}")
            self.assertFalse((self.root / f"extract{index}").exists())

    def test_zip_symlink_and_duplicates(self):
        bad = self.root / "link.apk"
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr(info, "../private")
        with self.assertRaises(ToolError):
            apk.open_archive(bad)
        duplicate = self.root / "duplicate.apk"
        with zipfile.ZipFile(duplicate, "w") as z:
            z.writestr("a//b", "1")
            z.writestr("a/b", "2")
        with self.assertRaises(ToolError):
            apk.open_archive(duplicate)

    def test_replace_strips_signatures_and_preserves_other_entries(self):
        replacement = self.root / "config.txt"
        replacement.write_text("changed")
        result = self.root / "changed.apk"
        before = sha256(self.apk)
        apk.replace_entry(self.apk, "assets/config.txt", replacement, result)
        with zipfile.ZipFile(result) as z:
            self.assertEqual(z.read("assets/config.txt"), b"changed")
            self.assertEqual(z.read("AndroidManifest.xml"), MANIFEST)
            self.assertNotIn("META-INF/CERT.SF", z.namelist())
        self.assertEqual(sha256(self.apk), before)
        comparison = apk.compare(self.apk, result)
        self.assertEqual(comparison["changed"], ["assets/config.txt"])
        self.assertEqual(comparison["removed"], ["META-INF/CERT.SF"])

    def test_pattern_wildcards_chunk_boundary(self):
        path = self.root / "boundary.so"
        path.write_bytes(b"\0" * (4 * 1024 ** 2 - 2) + b"\xaa\xbb\xcc\xdd" + b"\0")
        self.assertEqual(binary.scan(path, "AA ?? CC DD")["offsets"], [4 * 1024 ** 2 - 2])
        with self.assertRaises(ToolError):
            binary.scan(path, "?? ??")

    def test_binary_patch_precondition_and_input_unchanged(self):
        path = self.root / "test.so"
        path.write_bytes(bytes.fromhex("0001020304"))
        out = self.root / "patched.so"
        with self.assertRaises(ToolError):
            binary.patch(path, out, 1, "ffff", "aabb")
        self.assertFalse(out.exists())
        binary.patch(path, out, 1, "0102", "aabb")
        self.assertEqual(path.read_bytes(), bytes.fromhex("0001020304"))
        self.assertEqual(out.read_bytes(), bytes.fromhex("00aabb0304"))

    def test_strings_across_read_boundary(self):
        path = self.root / "strings.so"
        path.write_bytes(b"\0" * (1024 ** 2 - 3) + b"abcdefghi\0")
        hits = binary.strings(path)
        self.assertEqual(hits, [{"offset": 1024 ** 2 - 3, "hex_offset": hex(1024 ** 2 - 3), "text": "abcdefghi"}])

    def test_recursive_search_text_native_and_hex(self):
        tree = self.root / "tree"
        apk.extract(self.apk, tree)
        text = search.search(tree, query="enabled", glob="*.txt")
        self.assertEqual(text["hits"][0]["line"], 2)
        self.assertEqual(text["hits"][0]["file"], "assets/config.txt")
        native = search.search(tree, preset="jni")
        self.assertEqual(native["hits"][0]["kind"], "binary string")
        self.assertEqual(search.search(tree, hex_pattern="4A 61 76 61", glob="*.so")["hits"][0]["offset"], 1)
        self.assertEqual(search.search(tree, query="ENABLED", ignore_case=True)["hits"][0]["line"], 2)

    def test_recipe_text_xml_and_bytes(self):
        tree = self.root / "tree"
        apk.extract(self.apk, tree)
        rules = [
            {"path": "assets/config.txt", "kind": "text_replace", "find": "enabled=true", "replace": "enabled=false", "expected_matches": 1},
            {"path": "AndroidManifest.xml", "kind": "xml_set_attribute", "xpath": "./application", "attribute": "android:allowBackup", "expected": "true", "value": "false", "expected_matches": 1},
            {"path": "lib/arm64-v8a/libil2cpp.so", "kind": "binary_patch", "offset": "0x1", "find": "4a617661", "replace": "4a415641", "expected_matches": 1},
        ]
        recipe = self.recipe(rules)
        preview = recipes.plan(recipe, tree)
        self.assertEqual(len(preview["files"]), 3)
        self.assertFalse((self.root / "patched").exists())
        recipes.apply(recipe, tree, self.root / "patched")
        patched = self.root / "patched"
        self.assertIn("enabled=false", (patched / "assets/config.txt").read_text())
        summary = manifest_summary(parse_manifest((patched / "AndroidManifest.xml").read_bytes()))
        self.assertEqual(summary["application"]["allowBackup"], "false")
        self.assertIn("enabled=true", (tree / "assets/config.txt").read_text())
        self.assertTrue((patched / "uat-patch-report.json").exists())

    def test_recipe_failure_is_atomic(self):
        tree = self.root / "tree"
        apk.extract(self.apk, tree)
        rule = {"path": "assets/config.txt", "kind": "text_replace", "find": "missing", "replace": "new", "expected_matches": 1}
        recipe = self.recipe([rule])
        with self.assertRaises(ToolError):
            recipes.apply(recipe, tree, self.root / "patched")
        self.assertFalse((self.root / "patched").exists())
        rule["path"] = "../outside.txt"
        with self.assertRaises(ToolError):
            recipes.plan(self.recipe([rule]), tree)

    def test_recipe_sha_and_length_guards(self):
        tree = self.root / "tree"
        apk.extract(self.apk, tree)
        rule = {"path": "assets/config.txt", "kind": "text_replace", "find": "true", "replace": "false", "expected_matches": 1, "sha256": "0" * 64}
        with self.assertRaises(ToolError):
            recipes.plan(self.recipe([rule]), tree)
        rule = {"path": "lib/arm64-v8a/libil2cpp.so", "kind": "bytes_replace", "find": "4a61", "replace": "4a", "expected_matches": 1}
        with self.assertRaises(ToolError):
            recipes.plan(self.recipe([rule]), tree)

    def test_recipe_output_and_symlink_guards(self):
        tree = self.root / "tree"
        apk.extract(self.apk, tree)
        rule = {"path": "assets/config.txt", "kind": "text_replace", "find": "true", "replace": "false", "expected_matches": 1}
        recipe = self.recipe([rule])
        with self.assertRaises(ToolError):
            recipes.apply(recipe, tree, tree / "inside")
        (tree / "link").symlink_to(self.root / "recipe.json")
        with self.assertRaises(ToolError):
            recipes.apply(recipe, tree, self.root / "patched")

    def test_original_provenance(self):
        root = self.root / "project"
        project.create(self.apk, root)
        self.assertEqual(project.load(root)[1]["original_sha256"], sha256(self.apk))
        (root / "original.apk").chmod(0o600)
        (root / "original.apk").write_bytes(b"changed")
        with self.assertRaises(ToolError):
            project.load(root)

    def test_truncated_axml_rejected(self):
        for data in [b"", b"\x03\x00\x08\x00", struct.pack("<HHI", 3, 8, 100), struct.pack("<HHI", 3, 8, 8)]:
            with self.assertRaises(ToolError):
                parse_manifest(data)

    def test_invalid_dex_rejected(self):
        path = self.root / "classes.dex"
        path.write_bytes(b"dex\n035\0" + b"\0" * 104)
        with self.assertRaises(ToolError):
            binary.dex_info(path)

    def test_proc_map_parser(self):
        maps = parse_maps("1000-2000 r-xp 00001000 08:01 123 /data/lib name.so\n")
        self.assertEqual(maps[0]["path"], "/data/lib name.so")
        self.assertEqual(maps[0]["file_offset"], 4096)

    @unittest.skipUnless(Path("/proc/self/mem").exists(), "Linux /proc required")
    def test_live_module_dump_of_own_mapping(self):
        path = self.root / "owned.so"
        path.write_bytes(b"uat-test" + b"\0" * (mmap.PAGESIZE - 8))
        out = self.root / "snapshot.bin"
        out.touch()
        with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapping:
            report = dump(os.getpid(), path.name, out, mmap.PAGESIZE * 2)
            self.assertEqual(out.read_bytes()[:8], b"uat-test")
            self.assertEqual(report["copied_bytes"], mmap.PAGESIZE)
            with self.assertRaises(ValueError):
                dump(os.getpid(), path.name, out, 1)


if __name__ == "__main__":
    unittest.main()
