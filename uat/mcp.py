"""Dependency-free, read-only MCP stdio adapter for local coding agents."""
import json
import sys
from pathlib import Path

from . import __version__, apk, binary, search
from .common import ToolError


def _schema(properties, required):
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


PATH = {"type": "string", "description": "File/directory path inside the configured workspace"}
LIMIT = {"type": "integer", "minimum": 1, "maximum": 5000, "default": 500}

TOOLS = [
    {"name": "inspect_apk", "description": "APK manifest summary, permissions, engine hints, ABI and entry lists",
     "inputSchema": _schema({"path": PATH}, ["path"])},
    {"name": "read_manifest", "description": "Decode APK binary manifest into XML",
     "inputSchema": _schema({"path": PATH}, ["path"])},
    {"name": "search_files", "description": "Find literal strings or marker presets in source, smali, resources, DEX and native files",
     "inputSchema": _schema({"path": PATH, "query": {"type": "string"},
                            "preset": {"type": "string", "enum": sorted(search.PRESETS)},
                            "glob": {"type": "string", "default": "*"}, "limit": LIMIT,
                            "ignore_case": {"type": "boolean", "default": False}}, ["path"])},
    {"name": "binary_info", "description": "Identify and hash ELF, DEX or IL2CPP metadata",
     "inputSchema": _schema({"path": PATH}, ["path"])},
    {"name": "dex_info", "description": "Summarize DEX tables and classes, with SHA-1 and Adler-32 integrity checks",
     "inputSchema": _schema({"path": PATH, "limit": LIMIT}, ["path"])},
    {"name": "binary_strings", "description": "Read printable ASCII strings and file offsets",
     "inputSchema": _schema({"path": PATH, "limit": LIMIT, "contains": {"type": "string"},
                            "minimum": {"type": "integer", "minimum": 1, "maximum": 1024, "default": 6}}, ["path"])},
    {"name": "binary_scan", "description": "Search hex-byte patterns with ?? wildcards; results are file offsets",
     "inputSchema": _schema({"path": PATH, "pattern": {"type": "string"}, "limit": LIMIT}, ["path", "pattern"])},
    {"name": "elf_report", "description": "Read native headers, sections and dependencies using readelf",
     "inputSchema": _schema({"path": PATH}, ["path"])},
    {"name": "native_functions", "description": "Read Ghidra/IDA exported functions, pseudocode, assembly and caller references",
     "inputSchema": _schema({"path": PATH, "query": {"type": "string"}, "limit": LIMIT}, ["path"])},
]


class Server:
    def __init__(self, root):
        self.root = Path(root).expanduser().resolve()
        if not self.root.is_dir():
            raise ToolError("MCP root must be an existing directory")

    def _path(self, value):
        path = Path(value).expanduser()
        path = path.resolve() if path.is_absolute() else (self.root / path).resolve()
        if not path.is_relative_to(self.root):
            raise ToolError("Path is outside the configured MCP workspace")
        return path

    def call(self, name, args):
        definition = next((t for t in TOOLS if t["name"] == name), None)
        if definition is None:
            raise ToolError(f"Unknown tool: {name}")
        schema = definition["inputSchema"]
        if not isinstance(args, dict) or set(args) - set(schema["properties"]):
            raise ToolError("Unexpected tool arguments")
        if any(key not in args for key in schema["required"]):
            raise ToolError("Missing required tool arguments")
        for key, value in args.items():
            field = schema["properties"][key]
            kind = field["type"]
            if ((kind == "string" and not isinstance(value, str)) or
                    (kind == "integer" and type(value) is not int) or
                    (kind == "boolean" and type(value) is not bool)):
                raise ToolError(f"Invalid type for {key}")
            if kind == "integer" and not field["minimum"] <= value <= field["maximum"]:
                raise ToolError(f"Invalid range for {key}")
            if "enum" in field and value not in field["enum"]:
                raise ToolError(f"Invalid choice for {key}")
        path = self._path(args["path"])
        limit = args.get("limit", 500)
        if name == "inspect_apk":
            result = apk.inspect(path)
        elif name == "read_manifest":
            result = apk.manifest_xml(path)
        elif name == "search_files":
            if ("query" in args) == ("preset" in args):
                raise ToolError("Specify exactly one of query or preset")
            result = search.search(path, query=args.get("query"), preset=args.get("preset"),
                                   glob=args.get("glob", "*"), limit=limit, ignore_case=args.get("ignore_case", False))
        elif name == "binary_info":
            result = binary.info(path)
        elif name == "dex_info":
            result = binary.dex_info(path, limit)
        elif name == "binary_strings":
            result = binary.strings(path, args.get("minimum", 6), limit, args.get("contains"))
        elif name == "binary_scan":
            result = binary.scan(path, args["pattern"], limit)
        elif name == "elf_report":
            result = binary.elf_report(path)
        else:
            if not path.is_file() or path.stat().st_size > 128 * 1024 ** 2:
                raise ToolError("Native report must be an existing JSON file smaller than 128 MiB")
            report = json.loads(path.read_text())
            if not isinstance(report, dict) or not isinstance(report.get("functions"), list):
                raise ToolError("Expected a Ghidra/IDA native.json report")
            query = args.get("query", "").lower()
            functions = [f for f in report["functions"] if isinstance(f, dict) and
                         (not query or query in str(f.get("name", "")).lower() or query in str(f.get("pseudocode", "")).lower())]
            result = {"provider": report.get("provider"), "functions": functions[:limit],
                      "matching_functions": len(functions), "truncated": len(functions) > limit}
        text = result if isinstance(result, str) else json.dumps(result, indent=2, ensure_ascii=False)
        if len(text) > 1024 * 1024:
            text = text[:1024 * 1024] + "\n[Result truncated; narrow the request.]"
        return {"content": [{"type": "text", "text": text}], "isError": False}

    def handle(self, request):
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}}
        if "id" not in request:
            return None
        result = {"jsonrpc": "2.0", "id": request["id"]}
        method = request["method"]
        params = request.get("params", {})
        if not isinstance(params, dict):
            result["error"] = {"code": -32602, "message": "Params must be an object"}
        elif method == "initialize":
            version = params.get("protocolVersion")
            version = version if version in ("2024-11-05", "2025-03-26", "2025-06-18") else "2024-11-05"
            result["result"] = {"protocolVersion": version, "capabilities": {"tools": {}},
                                "serverInfo": {"name": "ultimate-android-toolkit", "version": __version__},
                                "instructions": f"Read-only analysis inside {self.root}. File offsets are not live addresses. Editing/signing require explicit CLI commands."}
        elif method == "ping":
            result["result"] = {}
        elif method == "tools/list":
            result["result"] = {"tools": TOOLS}
        elif method == "tools/call":
            try:
                result["result"] = self.call(params.get("name"), params.get("arguments", {}))
            except (ToolError, OSError, ValueError) as exc:
                result["result"] = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        else:
            result["error"] = {"code": -32601, "message": "Method not found"}
        return result


def serve(root):
    server = Server(root)
    # MCP stdio uses one JSON-RPC message per line. Stdout is reserved for protocol messages.
    for line in sys.stdin:
        if len(line) > 1024 * 1024:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Message exceeds 1 MiB"}}
        else:
            try:
                response = server.handle(json.loads(line))
            except json.JSONDecodeError:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Invalid JSON"}}
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)
