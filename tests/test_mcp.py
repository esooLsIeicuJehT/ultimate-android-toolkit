import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from uat.common import ToolError
from uat.mcp import Server


class MCPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "config.txt").write_text("example marker\n")
        self.server = Server(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def request(self, method, params=None):
        return self.server.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})

    def test_initialize_and_read_only_tools(self):
        response = self.request("initialize", {"protocolVersion": "2025-06-18"})
        self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")
        tools = self.request("tools/list")["result"]["tools"]
        self.assertIn("search_files", [t["name"] for t in tools])
        self.assertFalse(any("patch" in t["name"] or "sign" in t["name"] for t in tools))

    def test_search_and_outside_workspace_denial(self):
        response = self.request("tools/call", {"name": "search_files", "arguments": {"path": ".", "query": "marker"}})
        self.assertFalse(response["result"]["isError"])
        findings = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(findings["hits"][0]["line"], 1)
        denied = self.request("tools/call", {"name": "binary_info", "arguments": {"path": "../private.txt"}})
        self.assertTrue(denied["result"]["isError"])

    def test_argument_validation(self):
        for args in ({"path": ".", "query": "a", "limit": 0}, {"path": ".", "query": "a", "extra": True},
                     {"path": ".", "query": "a", "limit": "500"}, {"path": ".", "query": "a", "preset": "jni"}):
            response = self.request("tools/call", {"name": "search_files", "arguments": args})
            self.assertTrue(response["result"]["isError"])

    def test_native_report_functions_are_searchable(self):
        (self.root / "native.json").write_text(json.dumps({"provider": "ghidra", "functions": [
            {"name": "uat_add", "pseudocode": "return a + b;"}, {"name": "other", "pseudocode": "return 0;"}]}))
        response = self.server.call("native_functions", {"path": "native.json", "query": "uat_add"})
        report = json.loads(response["content"][0]["text"])
        self.assertEqual(report["matching_functions"], 1)
        self.assertEqual(report["functions"][0]["name"], "uat_add")

    def test_symlink_outside_workspace_denied(self):
        (self.root / "link").symlink_to("/etc/hosts")
        with self.assertRaises(ToolError):
            self.server.call("binary_info", {"path": "link"})

    def test_stdio_protocol_no_status_output(self):
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "binary_info", "arguments": {"path": "config.txt"}}},
        ]
        result = subprocess.run([sys.executable, "-m", "uat", "mcp", "--root", str(self.root)],
                                input="\n".join(json.dumps(m) for m in messages) + "\n", capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])["id"], 2)
        self.assertEqual(json.loads(lines[1])["result"]["isError"], False)
