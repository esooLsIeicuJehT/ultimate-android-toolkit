import argparse
import sys
from pathlib import Path

from . import __version__, analysis, apk, binary, device, external, frida_tools, native, project, recipes, search, signing
from .common import ToolError, emit, new_output
from .doctor import doctor


def positive(value):
    try:
        number = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected an integer, optionally 0x-prefixed") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("Must be greater than zero")
    return number


def nonnegative(value):
    number = int(value, 0)
    if number < 0:
        raise argparse.ArgumentTypeError("Must be nonnegative")
    return number


def parser():
    p = argparse.ArgumentParser(prog="uat", description="Termux APK analysis, editing, signing, and game research")
    p.add_argument("--version", action="version", version=__version__)
    groups = p.add_subparsers(dest="group")

    def command(parent, name, description, function, text=False, report=True):
        c = parent.add_parser(name, help=description, description=description)
        c.set_defaults(handler=function, text_output=text)
        if report:
            c.add_argument("--report", help="Save JSON (or text) output to a new file")
        return c

    def group(name, description):
        g = groups.add_parser(name, help=description)
        return g.add_subparsers(dest="command", required=True)

    def sign_options(c, required=True):
        c.add_argument("--keystore", required=required)
        c.add_argument("--alias", default="uat")
        c.add_argument("--password-env", help="Environment variable holding the keystore password; otherwise prompts privately")
        c.add_argument("--key-password-env", help="Separate key password for existing JKS keys, if needed")
        c.add_argument("--min-sdk", type=positive, help="Explicit signer minimum SDK override")

    def sign_kwargs(a):
        return {key: getattr(a, key) for key in ("alias", "password_env", "key_password_env", "min_sdk")}

    def via(c):
        c.add_argument("--via", choices=["local", "root", "adb"], default="local")

    c = command(groups, "doctor", "Check installed tools and device capabilities", lambda a: doctor(a.root))
    c.add_argument("--root", action="store_true", help="Explicitly request an su root check")
    command(groups, "menu", "Interactive terminal menu", lambda a: __import__("uat.menu", fromlist=["menu"]).menu(), report=False)
    c = command(groups, "mcp", "Serve read-only analysis tools to a local MCP agent over stdio", lambda a: __import__("uat.mcp", fromlist=["serve"]).serve(a.root), report=False)
    c.add_argument("--root", default=".", help="Restrict all analysis paths to this workspace")

    g = group("apk", "Inspect, extract, decode, rebuild, compare, align, sign, and verify")
    c = command(g, "analyze", "Extract, inspect DEX/native files, and run automatic search presets", lambda a: analysis.analyze(a.apk, a.out, a.decode, a.java))
    c.add_argument("apk"); c.add_argument("--out", required=True); c.add_argument("--decode", action="store_true"); c.add_argument("--java", action="store_true")
    c = command(g, "inspect", "APK report and engine hints", lambda a: apk.inspect(a.apk, a.hashes))
    c.add_argument("apk"); c.add_argument("--hashes", action="store_true")
    c = command(g, "manifest", "Read manifest XML without external tools", lambda a: apk.manifest_xml(a.apk), text=True)
    c.add_argument("apk")
    c = command(g, "list", "List ZIP entries", lambda a: apk.listing(a.apk, a.glob))
    c.add_argument("apk"); c.add_argument("--glob", default="*")
    c = command(g, "extract", "Extract APK, APKS, XAPK or APKM contents safely", lambda a: apk.extract(a.apk, a.out, a.glob))
    c.add_argument("apk"); c.add_argument("--out", required=True); c.add_argument("--glob", default="*")
    c = command(g, "compare", "Compare APK entry contents", lambda a: apk.compare(a.left, a.right))
    c.add_argument("left"); c.add_argument("right")
    c = command(g, "replace", "Replace one entry and export an unsigned copy", lambda a: apk.replace_entry(a.apk, a.entry, a.file, a.out))
    c.add_argument("apk"); c.add_argument("--entry", required=True); c.add_argument("--file", required=True); c.add_argument("--out", required=True)
    c = command(g, "decode", "Decode resources and smali using Apktool", lambda a: external.decode(a.apk, a.out, a.no_src, a.no_res))
    c.add_argument("apk"); c.add_argument("--out", required=True); c.add_argument("--no-src", action="store_true"); c.add_argument("--no-res", action="store_true")
    c = command(g, "build", "Build an editable Apktool directory into an unsigned APK", lambda a: external.build(a.directory, a.out))
    c.add_argument("directory"); c.add_argument("--out", required=True)
    c = command(g, "decompile", "Decompile DEX to approximate Java using JADX", lambda a: external.decompile(a.apk, a.out, a.threads))
    c.add_argument("apk"); c.add_argument("--out", required=True); c.add_argument("--threads", type=positive, default=2)
    c = command(g, "framework", "Install a vendor/framework resource APK for Apktool", lambda a: external.install_framework(a.apk))
    c.add_argument("apk")
    c = command(g, "align", "Align an APK before signing", lambda a: signing.align(a.apk, a.out))
    c.add_argument("apk"); c.add_argument("--out", required=True)
    c = command(g, "sign", "Align, sign with v1/v2/v3, verify, and export", lambda a: signing.sign(a.apk, a.out, a.keystore, **sign_kwargs(a)))
    c.add_argument("apk"); c.add_argument("--out", required=True); sign_options(c)
    c = command(g, "sign-set", "Align, sign and verify every APK in a split set with one key", lambda a: signing.sign_set(a.directory, a.out, a.keystore, **sign_kwargs(a)))
    c.add_argument("directory"); c.add_argument("--out", required=True); sign_options(c)
    c = command(g, "verify", "Verify signatures and print signing certificate fingerprints", lambda a: signing.verify(a.apk, a.min_sdk), text=True)
    c.add_argument("apk"); c.add_argument("--min-sdk", type=positive)

    g = group("key", "Create reusable signing keys and inspect certificates")
    c = command(g, "create", "Create a private RSA-3072 PKCS12 keystore", lambda a: signing.create_key(a.out, a.alias, a.password_env, a.dname))
    c.add_argument("--out", required=True); c.add_argument("--alias", default="uat"); c.add_argument("--password-env")
    c.add_argument("--dname", default="CN=Android Toolkit, OU=Development, O=Local, C=US")
    c = command(g, "info", "Show keystore certificate metadata", lambda a: signing.key_info(a.keystore, a.password_env), text=True)
    c.add_argument("keystore"); c.add_argument("--password-env")

    g = group("binary", "Analyze DEX/ELF, strings, byte patterns, and explicit file patches")
    c = command(g, "info", "Identify ELF/DEX/IL2CPP metadata and hash", lambda a: binary.info(a.file)); c.add_argument("file")
    c = command(g, "dex", "DEX counts, class names and integrity checks", lambda a: binary.dex_info(a.file, a.limit))
    c.add_argument("file"); c.add_argument("--limit", type=positive, default=1000)
    c = command(g, "strings", "Extract printable ASCII strings with offsets", lambda a: binary.strings(a.file, a.minimum, a.limit, a.contains))
    c.add_argument("file"); c.add_argument("--minimum", type=positive, default=6); c.add_argument("--limit", type=positive, default=1000); c.add_argument("--contains")
    c = command(g, "scan", "Search file byte patterns with ?? wildcards", lambda a: binary.scan(a.file, a.pattern, a.limit))
    c.add_argument("file"); c.add_argument("--pattern", required=True); c.add_argument("--limit", type=positive, default=1000)
    c = command(g, "patch", "Patch a new copy after matching expected bytes", lambda a: binary.patch(a.file, a.out, a.offset, a.expected, a.replace))
    c.add_argument("file"); c.add_argument("--out", required=True); c.add_argument("--offset", type=nonnegative, required=True)
    c.add_argument("--expected", required=True); c.add_argument("--replace", required=True)
    c = command(g, "hex", "Display bytes at a file offset", lambda a: binary.hexdump(a.file, a.offset, min(a.length, 65536)), text=True)
    c.add_argument("file"); c.add_argument("--offset", type=nonnegative, default=0); c.add_argument("--length", type=positive, default=256)
    c = command(g, "elf", "Read ELF headers, sections, mappings and dependencies", lambda a: binary.elf_report(a.file), text=True); c.add_argument("file")
    c = command(g, "symbols", "Export native symbol information as CSV", lambda a: binary.symbols(a.file, a.out))
    c.add_argument("file"); c.add_argument("--out", required=True)
    c = command(g, "disassemble", "Disassemble native code with architecture-compatible objdump", lambda a: binary.disassemble(a.file, a.out))
    c.add_argument("file"); c.add_argument("--out", required=True)

    c = command(groups, "search", "Recursively search Java, smali, resources, DEX and native files", lambda a: search.search(a.path, query=a.query, regex=a.regex, hex_pattern=a.hex, preset=a.preset, glob=a.glob, limit=a.limit, ignore_case=a.ignore_case))
    c.add_argument("path")
    choices = c.add_mutually_exclusive_group(required=True)
    choices.add_argument("--query"); choices.add_argument("--regex"); choices.add_argument("--hex"); choices.add_argument("--preset", choices=sorted(search.PRESETS))
    c.add_argument("--glob", default="*"); c.add_argument("--limit", type=positive, default=500); c.add_argument("--ignore-case", action="store_true")

    g = group("patch", "Preview and apply repeatable text, XML and binary patch recipes")
    c = command(g, "plan", "Validate all edits and show diffs/hashes without writing", lambda a: recipes.plan(a.recipe, a.root))
    c.add_argument("recipe"); c.add_argument("--root", required=True)
    c = command(g, "apply", "Validate all edits, then create a patched directory copy", lambda a: recipes.apply(a.recipe, a.root, a.out))
    c.add_argument("recipe"); c.add_argument("--root", required=True); c.add_argument("--out", required=True)

    g = group("project", "Preserve originals and track editable APK builds")
    c = command(g, "create", "Import an APK with provenance and an untouched original", lambda a: project.create(a.apk, a.out))
    c.add_argument("apk"); c.add_argument("--out", required=True)
    c = command(g, "info", "Validate original hash and show build history", lambda a: project.load(a.directory)[1]); c.add_argument("directory")
    c = command(g, "decode", "Decode a project's original into its decoded directory", lambda a: project.decode(a.directory)); c.add_argument("directory")
    c = command(g, "rebuild", "Rebuild a project, optionally align/sign/verify", lambda a: project.rebuild(a.directory, a.out, a.keystore, **sign_kwargs(a)))
    c.add_argument("directory"); c.add_argument("--out", required=True); sign_options(c, False)

    g = group("device", "Installed package export, installer handoff, logs and optional process access")
    c = command(g, "packages", "List visible installed packages", lambda a: device.packages(a.via)); via(c)
    c = command(g, "export", "Export an installed APK including all split APKs", lambda a: device.export(a.package, a.out, a.via))
    c.add_argument("package"); c.add_argument("--out", required=True); via(c)
    c = command(g, "install", "Request installation of one APK", lambda a: device.install(a.apk, a.via)); c.add_argument("apk"); via(c)
    c = command(g, "processes", "List processes visible to current UID or root", lambda a: device.proc("processes", root=a.root)); c.add_argument("--root", action="store_true")
    c = command(g, "maps", "Read accessible process memory mappings", lambda a: device.proc("maps", root=a.root, pid=a.pid))
    c.add_argument("pid", type=positive); c.add_argument("--root", action="store_true")
    c = command(g, "dump-module", "Read a mapped .so into a bounded memory snapshot", lambda a: device.proc("dump", root=a.root, pid=a.pid, module=a.module, output=a.out, max_bytes=a.max_bytes, allow_gaps=a.allow_gaps))
    c.add_argument("pid", type=positive); c.add_argument("--module", required=True); c.add_argument("--out", required=True)
    c.add_argument("--root", action="store_true"); c.add_argument("--max-bytes", type=positive, default=512 * 1024 ** 2); c.add_argument("--allow-gaps", action="store_true")
    c = command(g, "logcat", "Capture a bounded logcat snapshot", lambda a: device.logcat(a.pid, a.lines, a.via), text=True)
    c.add_argument("--pid", type=positive); c.add_argument("--lines", type=positive, default=200); via(c)

    g = group("engine", "Engine research helpers; native architecture and dumper compatibility are explicit")
    c = command(g, "il2cpp", "Run your compatible Il2CppDumper DLL on extracted files", lambda a: external.il2cpp(a.binary, a.metadata, a.tool, a.out))
    c.add_argument("binary"); c.add_argument("metadata"); c.add_argument("--tool", required=True); c.add_argument("--out", required=True)

    g = group("native", "Run separately installed Ghidra or IDA analysis locally or through SSH")
    for action, function in (("plan", native.plan), ("analyze", native.analyze)):
        c = command(g, action, "Preview provider commands" if action == "plan" else "Export native pseudocode, assembly, strings and references",
                    lambda a, f=function: f(a.file, a.out, a.provider, a.tool, a.remote, a.remote_work, min(a.limit, 5000)))
        c.add_argument("file"); c.add_argument("--out", required=True); c.add_argument("--provider", choices=["ghidra", "ida"], required=True)
        c.add_argument("--tool", help="Provider executable, or a local Ghidra installation directory")
        c.add_argument("--remote", help="Explicit SSH destination user@hostname")
        c.add_argument("--remote-work", default="/tmp"); c.add_argument("--limit", type=positive, default=500)

    g = group("frida", "Connect Frida, inspect runtime modules/exports, load scripts or trace functions")
    def frida_connection(c):
        connection = c.add_mutually_exclusive_group()
        connection.add_argument("--host", help="Frida server address, e.g. 127.0.0.1:27042")
        connection.add_argument("--usb", action="store_true")
    c = command(g, "status", "Check Frida client/device connection", lambda a: frida_tools.status(a.host, a.usb)); frida_connection(c)
    c = command(g, "ps", "List processes or installed applications visible to Frida", lambda a: frida_tools.processes(a.host, a.usb, a.apps))
    frida_connection(c); c.add_argument("--apps", action="store_true")
    c = command(g, "inspect", "Snapshot runtime modules and optional exports", lambda a: frida_tools.inspect(a.target, a.host, a.usb, a.spawn, a.module, a.exports, min(a.limit, 20000), a.wait))
    c.add_argument("target", help="PID/process name, or package/executable with --spawn"); frida_connection(c)
    c.add_argument("--spawn", action="store_true"); c.add_argument("--module"); c.add_argument("--exports", action="store_true")
    c.add_argument("--limit", type=positive, default=2000); c.add_argument("--wait", type=nonnegative, default=0, help="Wait up to ten seconds before a snapshot")
    c = command(g, "run", "Load your own Frida script into the selected target", lambda a: frida_tools.execute_script(a.target, a.script, a.host, a.usb, a.spawn), report=False)
    c.add_argument("target"); c.add_argument("--script", required=True); c.add_argument("--spawn", action="store_true"); frida_connection(c)
    c = command(g, "trace", "Trace explicit native/Java function patterns", lambda a: frida_tools.trace(a.target, a.include, a.java, a.out, a.host, a.usb, a.spawn))
    c.add_argument("target"); c.add_argument("--include", action="append", default=[]); c.add_argument("--java", action="append", default=[])
    c.add_argument("--out", required=True); c.add_argument("--spawn", action="store_true"); frida_connection(c)
    c = command(g, "server", "Run an installed Frida server in the foreground on loopback", lambda a: frida_tools.server(a.root, a.listen), report=False)
    c.add_argument("--root", action="store_true"); c.add_argument("--listen", default="127.0.0.1:27042")
    return p


def dispatch(args):
    result = args.handler(args)
    if result is None:
        return
    if args.text_output:
        if getattr(args, "report", None):
            new_output(args.report).write_text(result + "\n", encoding="utf-8")
            print(f"Saved: {args.report}")
        else:
            print(result)
    else:
        emit(result, getattr(args, "report", None))


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if not hasattr(args, "handler"):
        p.print_help()
        return 0
    try:
        dispatch(args)
        return 0
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except (ToolError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
