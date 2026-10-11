"""Opt-in real provider/runtime tests; no Android root or proprietary IDA required."""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from uat import frida_tools, native


class RuntimeIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("UAT_FRIDA_INTEGRATION") == "1" and importlib.util.find_spec("frida"), "Opt-in Frida binding required")
    def test_frida_local_child_modules_and_exports(self):
        child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"])
        try:
            report = frida_tools.inspect(str(child.pid), module="libc", exports=True, limit=50)
            self.assertEqual(report["pid"], child.pid)
            self.assertTrue(report["modules"])
            self.assertGreater(sum(len(m.get("exports", [])) for m in report["modules"]), 0)
        finally:
            child.terminate()
            child.wait(timeout=10)

    @unittest.skipUnless(os.environ.get("UAT_GHIDRA_TOOL") and shutil.which("cc"), "Opt-in Ghidra installation and C compiler required")
    def test_ghidra_real_pseudocode_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.c"
            source.write_text('const char *uat_label(void) { return "uat-example"; }\nint uat_add(int a, int b) { return a+b; }\n')
            library = root / "demo.so"
            subprocess.run(["cc", "-shared", "-fPIC", "-g", "-O0", str(source), "-o", str(library)], check=True)
            out = root / "ghidra"
            result = native.analyze(library, out, "ghidra", os.environ["UAT_GHIDRA_TOOL"], limit=30)
            self.assertTrue(result["decompiler_available"])
            import json
            report = json.loads((out / "native.json").read_text())
            function = next(f for f in report["functions"] if f["name"] == "uat_add")
            self.assertIn("return", function["pseudocode"])
            self.assertTrue(function["assembly"])


if __name__ == "__main__":
    unittest.main()
