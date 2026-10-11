import json
import re
import shlex
import shutil
import sys
from pathlib import Path

from .common import ToolError, executable, file_path, new_output, run, write_json


def android(argv, via="local", capture=True):
    if via == "adb":
        return run([executable("adb"), "shell", shlex.join([str(x) for x in argv])], capture=capture)
    if via == "root":
        command = [str(x) for x in argv]
        # Root shells may not inherit Termux's PATH. Resolve Android utilities explicitly.
        system = Path("/system/bin") / command[0]
        if system.is_file():
            command[0] = str(system)
        return run([executable("su"), "-c", shlex.join(command)], capture=capture)
    return run([executable(argv[0])] + argv[1:], capture=capture)


def package_name(value):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", value):
        raise ToolError("Invalid Android package name")
    return value


def packages(via="local"):
    raw = android(["pm", "list", "packages", "-f"], via)
    return sorted([{"package": line[8:].rsplit("=", 1)[-1], "apk_path": line[8:].rsplit("=", 1)[0]}
                   for line in raw.splitlines() if line.startswith("package:")], key=lambda x: x["package"])


def export(package, output, via="local"):
    package = package_name(package)
    output = new_output(output)
    raw = android(["pm", "path", package], via)
    paths = [line[8:] for line in raw.splitlines() if line.startswith("package:")]
    if not paths:
        raise ToolError("No APK paths returned. Check package visibility or try --via root / --via adb.")
    if any(not p.startswith("/") or not p.endswith(".apk") for p in paths):
        raise ToolError("Package manager returned invalid APK paths")
    output.mkdir(mode=0o700)
    try:
        for index, path in enumerate(paths):
            dest = output / f"{index:02d}-{Path(path).name}"
            if via == "adb":
                run([executable("adb"), "pull", path, dest])
            elif via == "root":
                # Use binary stdout so exported split APKs retain local ownership.
                import subprocess
                with dest.open("xb") as stream:
                    result = subprocess.run([executable("su"), "-c", shlex.join(["/system/bin/cat", path])], stdout=stream, stderr=subprocess.PIPE)
                if result.returncode:
                    raise ToolError(result.stderr.decode(errors="replace"))
            else:
                shutil.copyfile(path, dest)
    except Exception:
        shutil.rmtree(output)
        raise
    return {"output": str(output), "apk_count": len(paths), "split_package": len(paths) > 1,
            "note": "Split APKs must be kept as a compatible set. Export does not merge them into one APK."}


def install(path, via="local"):
    path = file_path(path)
    if via == "local":
        run([executable("termux-open"), "--view", str(path)])
        return {"status": "Requested Android installer; finish installation on the device."}
    if via == "adb":
        raw = run([executable("adb"), "install", "-r", path], capture=True)
    else:
        # Root can access Termux's private path; SELinux may still block the installer.
        raw = android(["pm", "install", "-r", path], via)
    if "Success" not in raw:
        raise ToolError(f"Android did not confirm installation: {raw.strip()}")
    return {"status": raw.strip()}


def proc(action, *, root=False, pid=None, module=None, output=None, max_bytes=512 * 1024 ** 2, allow_gaps=False):
    helper = Path(__file__).with_name("proc_helper.py")
    argv = [sys.executable, str(helper), action]
    if pid:
        argv += ["--pid", str(pid)]
    destination = None
    if action == "dump":
        destination = new_output(output)
        if not module or "/" in module or not module.endswith(".so"):
            raise ToolError("Use an exact native module basename, e.g. libil2cpp.so")
        if destination.with_suffix(destination.suffix + ".json").exists():
            raise ToolError("Dump metadata path already exists")
        destination.touch(mode=0o600, exist_ok=False)
        argv += ["--module", module, "--output", str(destination), "--max-bytes", str(max_bytes)]
        if allow_gaps:
            argv.append("--allow-gaps")
    try:
        if root:
            raw = run([executable("su"), "-c", shlex.join(argv)], capture=True)
        else:
            raw = run(argv, capture=True)
        data = json.loads(raw)
        if "error" in data:
            raise ToolError(data["error"])
        if destination:
            write_json(destination.with_suffix(destination.suffix + ".json"), data)
        return data
    except (ToolError, ValueError) as exc:
        if destination:
            destination.unlink(missing_ok=True)
        raise ToolError(f"Process access failed: {exc}. Other apps usually require root or a debuggable target; SELinux can still deny access.") from exc


def logcat(pid=None, lines=200, via="local"):
    argv = ["logcat", "-d", "-t", str(lines)]
    if pid:
        argv += ["--pid", str(pid)]
    return android(argv, via)
