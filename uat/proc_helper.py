"""Small standalone helper invoked directly for explicitly requested /proc reads.

It never changes SELinux, ptrace policy, target memory, or target app files.
"""
import argparse
import json
import os
from pathlib import Path


def parse_maps(text):
    result = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        start, end = [int(x, 16) for x in parts[0].split("-")]
        result.append({"start": start, "end": end, "permissions": parts[1],
                       "file_offset": int(parts[2], 16), "device": parts[3],
                       "inode": int(parts[4]), "path": parts[5] if len(parts) > 5 else ""})
    return result


def dump(pid, module, output, max_bytes, allow_gaps=False):
    regions = parse_maps(Path(f"/proc/{pid}/maps").read_text())
    matched_paths = {r["path"] for r in regions if Path(r["path"].removesuffix(" (deleted)")).name == module}
    if len(matched_paths) != 1:
        raise ValueError(f"Expected one exact mapped module basename; found {len(matched_paths)} paths")
    regions = [r for r in regions if r["path"] in matched_paths]
    base = min(r["start"] for r in regions)
    end = max(r["end"] for r in regions)
    size = end - base
    if size > max_bytes:
        raise ValueError(f"Mapping span is {size} bytes; exceeds max-bytes={max_bytes}")
    failures = []
    copied = 0
    # Caller allocates the file before escalation, preserving its ownership.
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as source, open(output, "r+b", buffering=0) as target:
        target.truncate(size)
        for region in regions:
            if "r" not in region["permissions"]:
                failures.append({"start": region["start"], "end": region["end"], "error": "Non-readable mapping"})
                if not allow_gaps:
                    raise PermissionError("Module contains non-readable mappings; inspect maps or explicitly use --allow-gaps")
                continue
            address = region["start"]
            while address < region["end"]:
                count = min(1024 ** 2, region["end"] - address)
                try:
                    source.seek(address)
                    block = source.read(count)
                    if len(block) != count:
                        raise OSError("Short memory read")
                    target.seek(address - base)
                    target.write(block)
                    copied += len(block)
                except OSError as exc:
                    failures.append({"start": address, "end": address + count, "error": str(exc)})
                    if not allow_gaps:
                        raise
                address += count
    return {"pid": pid, "module": module, "base": base, "span": size, "copied_bytes": copied,
            "regions": regions, "unreadable_ranges": failures,
            "layout": "Virtual address layout relative to base; holes are zero-filled. This is not a reconstructed on-disk ELF.",
            "note": "The process was not paused. Memory can change during capture."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["maps", "processes", "dump"])
    parser.add_argument("--pid", type=int)
    parser.add_argument("--module")
    parser.add_argument("--output")
    parser.add_argument("--max-bytes", type=int, default=512 * 1024 ** 2)
    parser.add_argument("--allow-gaps", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "maps":
            value = parse_maps(Path(f"/proc/{args.pid}/maps").read_text())
        elif args.action == "processes":
            value = []
            for path in Path("/proc").iterdir():
                if path.name.isdigit():
                    try:
                        raw = (path / "cmdline").read_bytes()[:4096]
                        value.append({"pid": int(path.name), "name": raw.split(b"\0")[0].decode(errors="replace")})
                    except OSError:
                        continue
        else:
            value = dump(args.pid, args.module, args.output, args.max_bytes, args.allow_gaps)
        print(json.dumps(value))
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
