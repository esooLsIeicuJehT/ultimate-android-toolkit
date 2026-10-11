import os
import shutil
from pathlib import Path

from .apk import open_archive
from .common import ToolError, executable, file_path, new_output, run


def framework_dir():
    base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "uat/frameworks"
    base.mkdir(parents=True, exist_ok=True)
    return base


def decode(path, output, no_src=False, no_res=False):
    path, output = file_path(path), new_output(output)
    with open_archive(path):
        pass
    argv = [executable("apktool"), "decode", "--frame-path", framework_dir(), "-o", output]
    if no_src:
        argv.append("--no-src")
    if no_res:
        argv.append("--no-res")
    run(argv + [path])
    return {"output": str(output), "status": "Decoded resources and smali are editable. Java decompilation uses apk decompile."}


def build(directory, output):
    directory = Path(directory).expanduser().resolve()
    if not (directory / "apktool.yml").is_file():
        raise ToolError("Expected an Apktool project containing apktool.yml")
    output = new_output(output)
    argv = [executable("apktool"), "build", "--frame-path", framework_dir(), "-o", output]
    # Desktop Apktool embeds desktop binaries. Android must use the native Termux aapt2.
    aapt2 = shutil.which("aapt2")
    termux = "/com.termux/" in os.environ.get("PREFIX", "") or Path("/system/build.prop").exists()
    if termux and not aapt2:
        raise ToolError("Android rebuilding requires native aapt2: pkg install aapt2")
    if aapt2:
        argv += ["--aapt", aapt2]
    run(argv + [directory])
    if not output.is_file():
        raise ToolError("Apktool did not produce an APK")
    return {"output": str(output), "status": "Unsigned. Use apk sign or project rebuild with a keystore."}


def decompile(path, output, threads=2):
    path, output = file_path(path), new_output(output)
    with open_archive(path):
        pass
    run([executable("jadx"), "--threads-count", str(threads), "-d", output, path])
    return {"output": str(output), "note": "Decompiled Java is approximate. Use decoded smali/resources for rebuilding."}


def install_framework(path):
    run([executable("apktool"), "if", "--frame-path", framework_dir(), file_path(path)])
    return {"framework_directory": str(framework_dir())}


def il2cpp(binary, metadata, tool, output):
    from .binary import info
    binary, metadata, tool = file_path(binary), file_path(metadata), file_path(tool)
    if info(binary)["format"] != "ELF" or info(metadata)["format"] != "Unity IL2CPP metadata":
        raise ToolError("Expected an ELF libil2cpp.so and unencrypted global-metadata.dat")
    output = new_output(output)
    if tool.suffix.lower() != ".dll":
        raise ToolError("Supply an Il2CppDumper .NET DLL. Desktop .exe files cannot run directly in Termux.")
    output.mkdir()
    run([executable("dotnet"), tool, binary, metadata, output])
    return {"output": str(output), "metadata_version": info(metadata)["metadata_version"],
            "note": "Compatibility depends on the dumper and Unity version. Some .NET builds require a separate Linux/proot environment."}
