# Local AI-agent analysis

The [REA article](https://cybersecuritynews.com/reverse-engineer-anything-tool/amp/) describes connecting coding agents to reverse-engineering tools through MCP. This toolkit includes its own small MCP stdio server for APK reports, manifest XML, file searches, binary identification, strings, byte scans, DEX summaries, and ELF reports.

```bash
uat mcp --root /absolute/path/to/research-workspace
```

The process reads JSON-RPC messages on stdin and writes responses on stdout. There is no network listener. All paths are restricted to the configured workspace. MCP tools are read-only; edits, root operations, decompilation, and signing are explicit CLI operations.

Register it manually in your coding agent's MCP configuration. For clients using `mcpServers`, adapt this example to the absolute paths on the machine running the client:

```json
{
  "mcpServers": {
    "android-toolkit": {
      "command": "/absolute/path/to/uat",
      "args": ["mcp", "--root", "/absolute/path/to/research-workspace"]
    }
  }
}
```

Find the executable with `command -v uat`. Codex uses its own MCP configuration format; the equivalent TOML entry is:

```toml
[mcp_servers.android_toolkit]
command = "/absolute/path/to/uat"
args = ["mcp", "--root", "/absolute/path/to/research-workspace"]
```

Client configuration is not changed by this toolkit's installer. The agent receives tool results, and handling of those results follows your agent/model settings.

Suggested investigation: analyze an APK with `uat apk analyze ... --decode --java`, then point the MCP workspace at that output. Ask the agent to identify relevant Java/smali files or native markers with paths and offsets, compare evidence across files, and propose a patch recipe with explicit preconditions. Review the recipe with `uat patch plan` and apply it through the CLI.

This server is not REA and does not bundle Ghidra, IDA, Hopper, or a native pseudocode engine. Deep native decompilation needs one of those separate tools, usually on a desktop. File search results and symbol reports alone do not establish correct game-function patches.
