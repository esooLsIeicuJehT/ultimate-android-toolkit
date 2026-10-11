import os
import platform
import shutil
import sys

from . import __version__
from .common import run

TOOLS = {
    "python": "Core CLI", "java": "Apktool and JADX", "javac": "Full JDK for Ghidra scripts", "keytool": "Keystore management",
    "apktool": "Decode and rebuild", "jadx": "Java decompilation", "apksigner": "Sign and verify",
    "zipalign": "APK alignment (normally supplied by Termux aapt)", "aapt2": "Native Android resource rebuilds",
    "readelf": "Native ELF reports and symbols", "objdump": "Native disassembly", "adb": "Optional ADB access",
    "termux-open": "Non-root installer handoff", "dotnet": "Optional user-supplied IL2CPP dumper",
    "su": "Optional root access",
    "frida": "Optional Frida script console", "frida-trace": "Optional native/Java runtime tracing",
    "frida-server": "Optional Android Frida server", "ssh": "Remote Ghidra/IDA analysis",
    "scp": "Remote provider file transfer", "analyzeHeadless": "Optional Ghidra headless analyzer",
    "idat64": "Optional licensed IDA headless analyzer",
}


def doctor(check_root=False):
    result = {"version": __version__, "python": sys.version.split()[0], "platform": platform.platform(),
              "architecture": platform.machine(), "termux": "/com.termux/" in os.environ.get("PREFIX", ""),
              "tools": {name: {"path": shutil.which(name), "purpose": purpose} for name, purpose in TOOLS.items()},
              "notes": ["su being present does not prove access. Use doctor --root to request a root check.",
                        "Static APK work does not require root. Other-app /proc access depends on Android security policy."]}
    if check_root:
        if shutil.which("su"):
            try:
                root_id = run([shutil.which("su"), "-c", "id -u"], capture=True, timeout=15).strip()
                result["root"] = {"granted": root_id == "0", "uid": root_id}
            except Exception as exc:
                result["root"] = {"granted": False, "error": str(exc)}
        else:
            result["root"] = {"granted": False, "error": "su is not installed"}
    return result
