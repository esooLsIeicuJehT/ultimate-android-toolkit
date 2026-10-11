import importlib
import os
import shlex
import time
from pathlib import Path

from .common import ToolError, executable, file_path, new_output, run


def binding():
    try:
        return importlib.import_module("frida")
    except ImportError as exc:
        raise ToolError("Frida Python binding is missing. Termux: pkg install root-repo && pkg install frida. See docs/providers.md.") from exc


def device(host=None, usb=False):
    frida = binding()
    try:
        if host:
            return frida.get_device_manager().add_remote_device(host)
        return frida.get_usb_device(timeout=10) if usb else frida.get_local_device()
    except Exception as exc:
        raise ToolError(f"Frida connection failed: {exc}. Match client/server versions and check the selected device.") from exc


def status(host=None, usb=False):
    frida = binding()
    target = device(host, usb)
    try:
        return {"client_version": frida.__version__, "device_id": target.id, "device_name": target.name,
                "process_count": len(target.enumerate_processes())}
    except Exception as exc:
        raise ToolError(f"Frida enumeration failed: {exc}") from exc


def processes(host=None, usb=False, apps=False):
    target = device(host, usb)
    try:
        if apps:
            return [{"identifier": a.identifier, "name": a.name, "pid": a.pid} for a in target.enumerate_applications()]
        return [{"pid": p.pid, "name": p.name} for p in target.enumerate_processes()]
    except Exception as exc:
        raise ToolError(f"Frida enumeration failed: {exc}") from exc


def inspect(target, host=None, usb=False, spawn=False, module=None, exports=False, limit=2000, wait=0):
    remote = device(host, usb)
    session = script = None
    pid = None
    try:
        if spawn:
            pid = remote.spawn([target])
            attach_target = pid
        else:
            attach_target = int(target) if str(target).isdigit() else target
        session = remote.attach(attach_target)
        source = Path(__file__).with_name("providers").joinpath("frida_snapshot.js").read_text()
        script = session.create_script(source)
        script.load()
        if pid is not None:
            remote.resume(pid)
            pid = None
        if wait:
            time.sleep(min(wait, 10))
        return script.exports_sync.snapshot(module or "", exports, limit)
    except Exception as exc:
        raise ToolError(f"Frida inspection failed: {exc}. Non-root targets require permitted/debuggable access or an app-integrated Gadget.") from exc
    finally:
        if pid is not None:
            # Do not leave a process spawned by this operation paused after an error.
            try:
                remote.resume(pid)
            except Exception:
                pass
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


def connection_flags(host=None, usb=False):
    return ["-H", host] if host else ["-U"] if usb else []


def target_flags(target, spawn=False):
    return ["-f", target] if spawn else ["-p", target] if str(target).isdigit() else ["-n", target]


def execute_script(target, script, host=None, usb=False, spawn=False):
    argv = [executable("frida")] + connection_flags(host, usb) + target_flags(target, spawn) + ["-l", str(file_path(script))]
    run(argv)
    return None


def trace(target, includes, java, output, host=None, usb=False, spawn=False):
    if not includes and not java:
        raise ToolError("Specify --include native patterns or --java Java method patterns")
    output = new_output(output)
    output.mkdir(mode=0o700)
    argv = [executable("frida-trace")] + connection_flags(host, usb) + target_flags(target, spawn)
    for pattern in includes:
        argv += ["-i", pattern]
    for pattern in java:
        argv += ["-j", pattern]
    run(argv, cwd=output)
    return {"output": str(output), "note": "Trace handlers are stored in this directory. Tracing instruments the selected process."}


def server(root=False, listen="127.0.0.1:27042"):
    if not listen.startswith("127.0.0.1:") or not listen[10:].isdigit():
        raise ToolError("The server helper binds only to 127.0.0.1:PORT")
    argv = [executable("frida-server"), "--listen", listen]
    if root:
        argv = [executable("su"), "-c", "exec " + shlex.join(argv)]
    env = os.environ.copy()
    env.pop("LD_PRELOAD", None)
    run(argv, env=env)
    return None
