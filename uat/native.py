"""Coordinate separately installed Ghidra/IDA providers locally or over SSH."""
import json
import os
import re
import shlex
import shutil
import uuid
from pathlib import Path

from .common import ToolError, executable, file_path, new_output, run, sha256, write_json

SCRIPTS = Path(__file__).with_name("providers")


def provider_tool(provider, supplied=None, remote=None):
    if supplied:
        if remote:
            if not supplied.startswith("/"):
                raise ToolError("Remote provider --tool must be an absolute path")
            return supplied
        path = Path(supplied).expanduser().resolve()
        if provider == "ghidra" and path.is_dir():
            path /= "support/analyzeHeadless"
        return str(file_path(path))
    if remote:
        raise ToolError("Specify the remote provider executable with --tool")
    if provider == "ghidra" and os.environ.get("GHIDRA_INSTALL_DIR"):
        return provider_tool(provider, os.environ["GHIDRA_INSTALL_DIR"])
    found = shutil.which("analyzeHeadless") if provider == "ghidra" else (shutil.which("idat64") or shutil.which("idat"))
    if not found:
        raise ToolError(f"No {provider} installation found. Supply --tool or --remote with --tool; see docs/providers.md.")
    return found


def provider_command(provider, tool, target, output, scripts, limit):
    output = Path(output)
    if provider == "ghidra":
        return [tool, str(output), "uat-project", "-import", str(target), "-scriptPath", str(scripts),
                "-postScript", "UATExport.java", str(output / "native.json"), str(limit),
                "-log", str(output / "analysis.log"), "-deleteProject"]
    # IDA parses a single -S argument containing the script path and its arguments.
    def quote(value):
        return '"' + str(value).replace('"', '\\"') + '"'
    script_args = quote(Path(scripts) / "ida_export.py") + " " + quote(output / "native.json") + " " + str(limit)
    return [tool, "-A", "-L" + str(output / "analysis.log"), "-o" + str(output / "target.i64"),
            "-S" + script_args, str(target)]


def plan(path, output, provider, tool=None, remote=None, remote_work="/tmp", limit=500):
    path = file_path(path)
    tool = provider_tool(provider, tool, remote)
    if remote and not re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+", remote):
        raise ToolError("Remote must be user@hostname (configure SSH aliases for ports or complex addresses)")
    if not re.fullmatch(r"/[A-Za-z0-9_/.-]*", remote_work) or ".." in Path(remote_work).parts:
        raise ToolError("Remote work directory must be a simple absolute path")
    if remote:
        working = Path(remote_work) / ("uat-" + uuid.uuid4().hex)
        argv = provider_command(provider, tool, working / "input.so", working, working, limit)
    else:
        working = Path(output).expanduser().absolute()
        argv = provider_command(provider, tool, path, working, SCRIPTS, limit)
    return {"provider": provider, "input": str(path), "input_sha256": sha256(path),
            "remote": remote, "working_directory": str(working), "command": argv,
            "note": "Providers must already be installed. IDA pseudocode requires an available matching decompiler license."}


def analyze(path, output, provider, tool=None, remote=None, remote_work="/tmp", limit=500):
    output = new_output(output)
    details = plan(path, output, provider, tool, remote, remote_work, limit)
    output.mkdir(mode=0o700)
    write_json(output / "provider-plan.json", details)
    if remote:
        ssh, scp = executable("ssh"), executable("scp")
        directory = details["working_directory"]
        run([ssh, remote, shlex.join(["mkdir", "-p", directory])])
        script = SCRIPTS / ("UATExport.java" if provider == "ghidra" else "ida_export.py")
        run([scp, str(file_path(path)), f"{remote}:{directory}/input.so"])
        run([scp, str(script), f"{remote}:{directory}/{script.name}"])
        run([ssh, remote, shlex.join(details["command"])])
        run([scp, f"{remote}:{directory}/native.json", str(output / "native.json")])
        # Remote artifacts are kept for review. No broad remote deletion is performed.
    else:
        run(details["command"])
    try:
        report = json.loads((output / "native.json").read_text())
    except (OSError, ValueError) as exc:
        raise ToolError(f"Provider produced no valid native.json. Inspect logs in {details['working_directory']}: {exc}") from exc
    if not isinstance(report, dict) or not isinstance(report.get("functions"), list):
        raise ToolError("Provider report has an unexpected schema; inspect native.json")
    return {"output": str(output), "provider": provider, "functions": len(report.get("functions", [])),
            "strings": len(report.get("strings", [])), "decompiler_available": report.get("decompiler_available"),
            "input_sha256": details["input_sha256"], "remote_working_directory": details["working_directory"] if remote else None,
            "note": "Provider addresses use the imported image layout; translate them before comparing to live process addresses."}
