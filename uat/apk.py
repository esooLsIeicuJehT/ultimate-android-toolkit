import fnmatch
import copy
import hashlib
import re
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET

from .axml import parse_manifest, manifest_summary
from .common import ToolError, file_path, new_output, sha256

MAX_TOTAL = 2 * 1024 ** 3
MAX_ENTRY = 512 * 1024 ** 2


def open_archive(path):
    try:
        archive = zipfile.ZipFile(file_path(path))
        infos = archive.infolist()
        if len(infos) > 100000:
            raise ToolError("Archive contains more than 100,000 entries")
        seen = set()
        total = 0
        for info in infos:
            name = info.filename
            parts = PurePosixPath(name).parts
            if (not parts or name.startswith("/") or "\\" in name or
                    any(p in ("..", ".") for p in name.split("/")) or
                    any(ord(c) < 32 for c in name) or ":" in parts[0]):
                raise ToolError(f"Unsafe archive path: {name!r}")
            canonical = "/".join(parts)
            if canonical in seen:
                raise ToolError(f"Duplicate archive path: {name!r}")
            seen.add(canonical)
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ToolError(f"Archive symlink rejected: {name!r}")
            if info.flag_bits & 1:
                raise ToolError("Encrypted ZIP entries are unsupported")
            if info.file_size > MAX_ENTRY:
                raise ToolError(f"Entry exceeds 512 MiB limit: {name}")
            if info.file_size > 16 * 1024 ** 2 and info.file_size > max(1, info.compress_size) * 1000:
                raise ToolError(f"Suspicious compression ratio: {name}")
            total += info.file_size
        if total > MAX_TOTAL:
            raise ToolError("Archive expands beyond the 2 GiB limit")
        return archive
    except (zipfile.BadZipFile, OSError) as exc:
        raise ToolError(f"Invalid APK/ZIP: {exc}") from exc
    except Exception:
        if "archive" in locals():
            archive.close()
        raise


def _entry_hash(archive, name):
    digest = hashlib.sha256()
    with archive.open(name) as stream:
        for block in iter(lambda: stream.read(1024 ** 2), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest(path):
    with open_archive(path) as archive:
        if "AndroidManifest.xml" not in archive.namelist():
            raise ToolError("No AndroidManifest.xml. This may be an APK bundle; use apk extract first.")
        if archive.getinfo("AndroidManifest.xml").file_size > 16 * 1024 ** 2:
            raise ToolError("Manifest exceeds 16 MiB")
        return parse_manifest(archive.read("AndroidManifest.xml"))


def manifest_xml(path):
    root = manifest(path)
    ET.indent(root)
    return ET.tostring(root, encoding="unicode")


def engine_hints(names):
    lower = [n.lower() for n in names]
    hints = []
    if any(n.endswith("libil2cpp.so") for n in lower):
        hints.append("Unity IL2CPP")
    elif any(n.endswith("libunity.so") or "assets/bin/data" in n for n in lower):
        hints.append("Unity")
    if any(n.endswith(("libue4.so", "libunreal.so")) or n.endswith(".pak") for n in lower):
        hints.append("Unreal (heuristic; version not determined)")
    if any(n.endswith("libgodot_android.so") for n in lower):
        hints.append("Godot")
    if any("libcocos" in n for n in lower):
        hints.append("Cocos")
    if any(n.endswith("libflutter.so") for n in lower):
        hints.append("Flutter")
    return hints


def inspect(path, hashes=False):
    path = file_path(path)
    with open_archive(path) as archive:
        names = archive.namelist()
        report = {
            "file": str(path), "bytes": path.stat().st_size, "sha256": sha256(path),
            "entry_count": len(names), "expanded_bytes": sum(i.file_size for i in archive.infolist()),
            "engine_hints": engine_hints(names),
            "abis": sorted({n.split("/")[1] for n in names if n.startswith("lib/") and len(n.split("/")) >= 3}),
            "native_libraries": sorted(n for n in names if n.startswith("lib/") and n.endswith(".so")),
            "dex_files": sorted(n for n in names if re.fullmatch(r"classes\d*\.dex", n)),
            "il2cpp_metadata": sorted(n for n in names if n.endswith("global-metadata.dat")),
            "embedded_apks": sorted(n for n in names if n.endswith(".apk")),
            "v1_signature_entries": sorted(n for n in names if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))),
            "signature_note": "ZIP entries do not establish signature validity. Use apk verify for v1/v2/v3 verification.",
        }
        if "AndroidManifest.xml" in names:
            report["manifest"] = manifest_summary(manifest(path))
        if hashes:
            report["entry_hashes"] = {i.filename: _entry_hash(archive, i.filename) for i in archive.infolist() if not i.is_dir()}
        return report


def listing(path, pattern="*"):
    with open_archive(path) as archive:
        return [{"name": i.filename, "bytes": i.file_size, "compressed_bytes": i.compress_size,
                 "compression": i.compress_type, "crc32": f"{i.CRC:08x}"}
                for i in archive.infolist() if fnmatch.fnmatchcase(i.filename, pattern)]


def extract(path, output, pattern="*"):
    output = new_output(output)
    with open_archive(path) as archive:
        selected = [i for i in archive.infolist() if fnmatch.fnmatchcase(i.filename, pattern)]
        if not selected:
            raise ToolError(f"No entries match {pattern!r}")
        # The new private directory prevents archive paths from following preexisting symlinks.
        output.mkdir(mode=0o700)
        try:
            for info in selected:
                dest = output.joinpath(*PurePosixPath(info.filename).parts)
                if info.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, dest.open("xb") as target:
                        shutil.copyfileobj(source, target, 1024 ** 2)
        except Exception:
            shutil.rmtree(output)
            raise
    return {"output": str(output), "entries": len(selected)}


def compare(left, right):
    with open_archive(left) as a, open_archive(right) as b:
        left_names = {i.filename for i in a.infolist() if not i.is_dir()}
        right_names = {i.filename for i in b.infolist() if not i.is_dir()}
        changed = []
        for name in sorted(left_names & right_names):
            if a.getinfo(name).file_size != b.getinfo(name).file_size or _entry_hash(a, name) != _entry_hash(b, name):
                changed.append(name)
        return {"left_sha256": sha256(left), "right_sha256": sha256(right),
                "added": sorted(right_names - left_names), "removed": sorted(left_names - right_names),
                "changed": changed,
                "note": "Compares entry contents. Signing blocks, ZIP metadata, and alignment are not compared."}


def replace_entry(path, entry, replacement, output):
    replacement = file_path(replacement)
    output = new_output(output)
    if replacement.stat().st_size > MAX_ENTRY:
        raise ToolError("Replacement exceeds 512 MiB")
    with open_archive(path) as archive:
        if entry not in archive.namelist() or archive.getinfo(entry).is_dir():
            raise ToolError(f"File entry does not exist: {entry}")
        with zipfile.ZipFile(output, "x") as target:
            for info in archive.infolist():
                upper = info.filename.upper()
                if upper.startswith("META-INF/") and (upper.endswith((".RSA", ".DSA", ".EC", ".SF")) or upper == "META-INF/MANIFEST.MF"):
                    continue
                with target.open(copy.copy(info), "w") as dest:
                    if info.filename == entry:
                        with replacement.open("rb") as source:
                            shutil.copyfileobj(source, dest, 1024 ** 2)
                    else:
                        with archive.open(info) as source:
                            shutil.copyfileobj(source, dest, 1024 ** 2)
    return {"output": str(output), "replaced": entry,
            "status": "Unsigned; run apk sign before installing. Resource/manifest changes should use apk decode/build."}
