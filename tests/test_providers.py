import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from uat import frida_tools, native
from uat.common import ToolError


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.binary = self.root / "input with spaces.so"
        self.binary.write_bytes(b"\x7fELF")

    def tearDown(self):
        self.temp.cleanup()

    def test_ghidra_plan_and_remote_validation(self):
        plan = native.plan(self.binary, self.root / "out", "ghidra", tool=sys.executable)
        self.assertIn(str(self.binary), plan["command"])
        self.assertIn("UATExport.java", plan["command"])
        self.assertFalse((self.root / "out").exists())
        remote = native.plan(self.binary, self.root / "out", "ghidra", "/opt/ghidra/support/analyzeHeadless", "me@desktop")
        self.assertTrue(remote["working_directory"].startswith("/tmp/uat-"))
        with self.assertRaises(ToolError):
            native.plan(self.binary, self.root / "out", "ghidra", "/opt/tool", "me@host;echo bad")
        with self.assertRaises(ToolError):
            native.plan(self.binary, self.root / "out", "ghidra", "/opt/tool", "me@host", "/tmp/../bad")

    def test_ida_arguments_preserve_spaces(self):
        plan = native.plan(self.binary, self.root / "out with spaces", "ida", tool=sys.executable)
        script_arg = next(a for a in plan["command"] if a.startswith("-S"))
        self.assertIn('"', script_arg)
        self.assertIn("out with spaces/native.json", script_arg)
        self.assertEqual(plan["command"][-1], str(self.binary))

    def test_provider_adapter_requires_actual_json(self):
        out = self.root / "out"

        def fake_provider(argv, **kwargs):
            (out / "native.json").write_text(json.dumps({"provider": "ghidra", "functions": [{"name": "test"}], "strings": [], "decompiler_available": True}))

        with patch("uat.native.run", side_effect=fake_provider):
            result = native.analyze(self.binary, out, "ghidra", tool=sys.executable)
        self.assertEqual(result["functions"], 1)
        self.assertEqual(result["decompiler_available"], True)
        with patch("uat.native.run"):
            with self.assertRaises(ToolError):
                native.analyze(self.binary, self.root / "missing-report", "ida", tool=sys.executable)

    def test_frida_read_only_snapshot_and_detach(self):
        device = MagicMock()
        script = device.attach.return_value.create_script.return_value
        script.exports_sync.snapshot.return_value = {"pid": 123, "modules": []}
        with patch("uat.frida_tools.device", return_value=device):
            result = frida_tools.inspect("123", module="libdemo.so", exports=True)
        self.assertEqual(result["pid"], 123)
        device.attach.assert_called_once_with(123)
        script.exports_sync.snapshot.assert_called_once_with("libdemo.so", True, 2000)
        script.unload.assert_called_once()
        device.attach.return_value.detach.assert_called_once()

    def test_frida_spawn_failure_resumes_target(self):
        device = MagicMock()
        device.spawn.return_value = 456
        device.attach.side_effect = RuntimeError("attach denied")
        with patch("uat.frida_tools.device", return_value=device):
            with self.assertRaises(ToolError):
                frida_tools.inspect("org.example.app", spawn=True)
        device.resume.assert_called_once_with(456)

    def test_frida_cli_flags_and_loopback_server(self):
        self.assertEqual(frida_tools.connection_flags("127.0.0.1:27042"), ["-H", "127.0.0.1:27042"])
        self.assertEqual(frida_tools.target_flags("org.example.app", True), ["-f", "org.example.app"])
        with self.assertRaises(ToolError):
            frida_tools.server(listen="0.0.0.0:27042")
