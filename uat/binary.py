import csv
import hashlib
import re
import shutil
import struct
import zlib
from pathlib import Path

from .common import ToolError, executable, file_path, new_output, run, sha256


def info(path):
    path = file_path(path)
    with path.open("rb") as stream:
        data = stream.read(112)
    result = {"file": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}
    if data.startswith(b"\x7fELF"):
        if len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
            raise ToolError("Invalid ELF header")
        endian = "<" if data[5] == 1 else ">"
        machine = struct.unpack_from(endian + "H", data, 18)[0]
        result.update(format="ELF", bits=32 if data[4] == 1 else 64,
                      endian="little" if data[5] == 1 else "big", machine=machine,
                      architecture={3: "x86", 40: "ARM", 62: "x86_64", 183: "AArch64"}.get(machine, "unknown"),
                      elf_type=struct.unpack_from(endian + "H", data, 16)[0])
    elif data.startswith(b"dex\n"):
        result.update(format="DEX", version=data[4:7].decode("ascii", errors="replace"))
    elif len(data) >= 8 and struct.unpack_from("<I", data)[0] == 0xFAB11BAF:
        result.update(format="Unity IL2CPP metadata", metadata_version=struct.unpack_from("<I", data, 4)[0])
    else:
        result["format"] = "unknown"
    return result


def dex_info(path, limit=1000):
    path = file_path(path)
    if path.stat().st_size > 512 * 1024 ** 2:
        raise ToolError("DEX exceeds 512 MiB")
    data = path.read_bytes()
    if len(data) < 112 or data[:4] != b"dex\n" or data[7] != 0:
        raise ToolError("Expected a standard DEX file (compact DEX is unsupported)")
    version = data[4:7].decode("ascii", errors="replace")
    if version not in ("035", "036", "037", "038", "039", "040"):
        raise ToolError(f"DEX {version} container layout is not supported by the built-in reader; use JADX")
    file_size, header_size, endian = struct.unpack_from("<III", data, 32)
    if file_size != len(data) or header_size != 112 or endian != 0x12345678:
        raise ToolError("Invalid or unsupported DEX header")

    def table(pos, stride):
        count, offset = struct.unpack_from("<II", data, pos)
        if count and (offset < 112 or offset + count * stride > len(data)):
            raise ToolError("DEX table extends outside the file")
        return count, offset

    strings_n, strings_at = table(56, 4)
    types_n, types_at = table(64, 4)
    protos_n, _ = table(72, 12)
    fields_n, _ = table(80, 8)
    methods_n, _ = table(88, 8)
    classes_n, classes_at = table(96, 32)

    def read_string(index):
        if index >= strings_n:
            raise ToolError("DEX string index out of bounds")
        at = struct.unpack_from("<I", data, strings_at + index * 4)[0]
        for _ in range(5):
            if at >= len(data):
                raise ToolError("Truncated DEX string")
            byte = data[at]
            at += 1
            if byte < 128:
                break
        else:
            raise ToolError("Invalid DEX string length")
        end = data.find(b"\0", at, min(len(data), at + 1024 ** 2))
        if end < 0:
            raise ToolError("Unterminated DEX string")
        return data[at:end].decode("utf-8", errors="replace")

    classes = []
    for index in range(min(classes_n, limit)):
        type_index = struct.unpack_from("<I", data, classes_at + index * 32)[0]
        if type_index >= types_n:
            raise ToolError("DEX class type out of bounds")
        string_index = struct.unpack_from("<I", data, types_at + type_index * 4)[0]
        classes.append(read_string(string_index))
    return {"version": version, "bytes": len(data), "strings": strings_n, "types": types_n,
            "prototypes": protos_n, "fields": fields_n, "methods": methods_n, "class_count": classes_n,
            "classes": classes, "classes_truncated": classes_n > limit,
            "sha1_valid": hashlib.sha1(data[32:]).digest() == data[12:32],
            "adler32_valid": zlib.adler32(data[12:]) & 0xFFFFFFFF == struct.unpack_from("<I", data, 8)[0]}


def strings(path, minimum=6, limit=1000, contains=None):
    path = file_path(path)
    hits = []
    pattern = re.compile(rb"[\x20-\x7e]{" + str(minimum).encode() + rb",}")
    tail = b""
    offset = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 ** 2)
            data = tail + chunk
            base = offset - len(tail)
            # Preserve runs spanning chunks, but bound unusually long runs to 8192 bytes.
            match = re.search(rb"[\x20-\x7e]+$", data) if chunk else None
            cut = match.start() if match and len(match.group()) <= 8192 else len(data)
            for found in pattern.finditer(data[:cut]):
                value = found.group()[:8192].decode("ascii")
                if contains is None or contains.lower() in value.lower():
                    hits.append({"offset": base + found.start(), "hex_offset": hex(base + found.start()), "text": value})
                    if len(hits) >= limit:
                        return hits
            tail = data[cut:]
            offset += len(chunk)
            if not chunk:
                return hits


def parse_pattern(value):
    tokens = value.split()
    if not tokens or len(tokens) > 65536:
        raise ToolError("Use 1 to 65536 space-separated hex bytes, with ?? wildcards")
    try:
        return [None if t in ("?", "??") else int(t, 16) if len(t) == 2 else -1 for t in tokens]
    except ValueError as exc:
        raise ToolError("Invalid hex pattern") from exc


def scan(path, pattern, limit=1000):
    path = file_path(path)
    values = parse_pattern(pattern)
    if any(v is not None and not 0 <= v <= 255 for v in values):
        raise ToolError("Invalid hex pattern")
    anchor_at = next((i for i, v in enumerate(values) if v is not None), None)
    if anchor_at is None:
        raise ToolError("Pattern needs at least one concrete byte")
    hits = []
    tail = b""
    offset = 0
    with path.open("rb") as stream:
        while chunk := stream.read(4 * 1024 ** 2):
            data = tail + chunk
            base = offset - len(tail)
            cursor = anchor_at
            last = len(data) - len(values)
            while True:
                found = data.find(bytes([values[anchor_at]]), cursor)
                start = found - anchor_at
                if found < 0 or start > last:
                    break
                if start >= 0 and all(v is None or data[start + i] == v for i, v in enumerate(values)):
                    hits.append(base + start)
                    if len(hits) >= limit:
                        return {"offsets": hits, "hex_offsets": [hex(x) for x in hits], "limit_reached": True}
                cursor = found + 1
            tail = data[-(len(values) - 1):] if len(values) > 1 else b""
            offset += len(chunk)
    return {"offsets": hits, "hex_offsets": [hex(x) for x in hits], "limit_reached": False}


def patch(path, output, offset, expected, replacement):
    path = file_path(path)
    output = new_output(output)
    try:
        before, after = bytes.fromhex(expected), bytes.fromhex(replacement)
    except ValueError as exc:
        raise ToolError("Expected and replacement must be hex bytes") from exc
    if not before or len(before) != len(after) or offset < 0:
        raise ToolError("Patch must have equal nonzero byte lengths and a nonnegative file offset")
    with path.open("rb") as source:
        source.seek(offset)
        if source.read(len(before)) != before:
            raise ToolError("Expected bytes do not match. Input was not modified.")
        source.seek(0)
        with output.open("xb") as target:
            shutil.copyfileobj(source, target, 1024 ** 2)
    with output.open("r+b") as target:
        target.seek(offset)
        target.write(after)
    return {"input_sha256": sha256(path), "output_sha256": sha256(output),
            "output": str(output), "offset": offset, "before": before.hex(), "after": after.hex()}


def hexdump(path, offset=0, length=256):
    with file_path(path).open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    return "\n".join(f"{offset + i:08x}  {data[i:i+16].hex(' '):47}  " +
                     "".join(chr(c) if 32 <= c < 127 else "." for c in data[i:i+16])
                     for i in range(0, len(data), 16))


def elf_report(path):
    path = file_path(path)
    if info(path)["format"] != "ELF":
        raise ToolError("Expected an ELF native library")
    tool = shutil.which("llvm-readelf") or executable("readelf")
    return run([tool, "-h", "-l", "-S", "-d", "-W", path], capture=True)


def symbols(path, output):
    path = file_path(path)
    output = new_output(output)
    tool = shutil.which("llvm-readelf") or executable("readelf")
    raw = run([tool, "--symbols", "--wide", path], capture=True)
    rows = []
    for line in raw.splitlines():
        match = re.match(r"\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)", line)
        if match:
            rows.append(match.groups())
    with output.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["value_hex", "size", "type", "binding", "visibility", "section", "name"])
        writer.writerows(rows)
    return {"output": str(output), "symbols": len(rows),
            "note": "ELF symbol values are not absolute live-process addresses. Stripped binaries expose fewer symbols."}


def disassemble(path, output):
    path = file_path(path)
    output = new_output(output)
    tool = shutil.which("llvm-objdump") or executable("objdump")
    with output.open("x", encoding="utf-8") as stream:
        import subprocess
        result = subprocess.run([tool, "-d", "-C", str(path)], stdout=stream, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        output.unlink()
        raise ToolError(f"Disassembly failed; install an objdump supporting this architecture. {result.stderr[-2000:]}")
    return {"output": str(output)}
