"""Search untrusted decoded files without executing their contents."""
import fnmatch
import re
from pathlib import Path

from . import binary
from .common import ToolError, file_path

PRESETS = {
    "endpoints": r"https?://[^\s\"'<>\\]{4,256}",
    "jni": r"(?:Java_[A-Za-z0-9_]{4,200}|JNI_OnLoad|RegisterNatives)",
    "unity": r"(?:il2cpp_[A-Za-z0-9_]{2,100}|global-metadata\.dat|UnityEngine\.[A-Za-z0-9_.]{2,100})",
    "unreal": r"(?:GWorld|GUObjectArray|FNamePool|/Script/[A-Za-z0-9_.]{2,100}|Unreal Engine)",
    "logging": r"(?:Landroid/util/Log;->[vdiew]|android\.util\.Log|System\.out\.print|__android_log_[a-z_]+)",
}


def files_under(root, glob="*", max_files=100000):
    root = Path(root).expanduser().resolve()
    if root.is_file():
        yield root, root.name
        return
    if not root.is_dir():
        raise ToolError(f"Search path not found: {root}")
    count = 0
    import os
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink() and d != ".git")
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file() or not fnmatch.fnmatchcase(relative, glob):
                continue
            count += 1
            if count > max_files:
                raise ToolError("Search exceeded 100,000 files; narrow --glob")
            yield path, relative


def search(root, *, query=None, regex=None, hex_pattern=None, preset=None, glob="*", limit=500, ignore_case=False):
    hits = []
    scanned = 0
    skipped = []
    if preset:
        regex = PRESETS[preset]
    if regex:
        if len(regex) > 4096:
            raise ToolError("Regex too long")
        try:
            compiled = re.compile(regex.encode("utf-8"), re.IGNORECASE if ignore_case else 0)
        except re.error as exc:
            raise ToolError(f"Invalid regex: {exc}") from exc
    else:
        compiled = None
    needle = query.encode("utf-8") if query is not None else None
    if needle == b"":
        raise ToolError("Search query cannot be empty")
    if needle and ignore_case:
        needle = needle.lower()
    for path, relative in files_under(root, glob):
        scanned += 1
        remaining = limit - len(hits)
        if hex_pattern:
            found = binary.scan(path, hex_pattern, remaining)["offsets"]
            hits.extend({"file": relative, "offset": offset, "hex_offset": hex(offset), "kind": "bytes"} for offset in found)
        elif path.stat().st_size > 128 * 1024 ** 2:
            skipped.append({"file": relative, "reason": "Over 128 MiB. Use binary scan/strings for large files."})
        else:
            data = path.read_bytes()
            text_file = b"\0" not in data[:8192]
            if compiled:
                matches = ((m.start(), m.end()) for m in compiled.finditer(data))
            else:
                haystack = data.lower() if ignore_case else data

                def find_all():
                    cursor = 0
                    while True:
                        at = haystack.find(needle, cursor)
                        if at < 0:
                            return
                        yield at, at + len(needle)
                        cursor = at + max(1, len(needle))
                matches = find_all()
            previous = 0
            line = 1
            for start, end in matches:
                if text_file:
                    line += data.count(b"\n", previous, start)
                    previous = start
                excerpt = data[max(0, start - 40):min(len(data), end + 80)].decode("utf-8", errors="replace")
                excerpt = "".join(c if c in "\t\n" or ord(c) >= 32 else "." for c in excerpt)
                hits.append({"file": relative, "offset": start, "hex_offset": hex(start),
                             "line": line if text_file else None, "match": data[start:end][:512].decode("utf-8", errors="replace"),
                             "context": excerpt[:700], "kind": "text" if text_file else "binary string"})
                if len(hits) >= limit:
                    break
        if len(hits) >= limit:
            break
    return {"hits": hits, "files_scanned": scanned, "skipped": skipped,
            "limit_reached": len(hits) >= limit,
            "note": "Offsets are file offsets. Presets are navigation hints, not semantic proof or live memory addresses."}
