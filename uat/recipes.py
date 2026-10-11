"""Deterministic bulk editing with preconditions and output-copy semantics."""
import difflib
import hashlib
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

from .axml import ANDROID
from .common import ToolError, file_path, new_output, write_json
from .search import files_under


def _path(root, value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ToolError("Recipe path must be a relative POSIX path")
    rel = PurePosixPath(value)
    if rel.is_absolute() or ".." in rel.parts or ":" in rel.parts[0]:
        raise ToolError("Recipe path escapes the input directory")
    path = root.joinpath(*rel.parts)
    if any(p.is_symlink() for p in [path, *path.parents] if p != root.parent):
        raise ToolError("Recipe paths cannot contain symlinks")
    if not path.is_file() or not path.resolve().is_relative_to(root):
        raise ToolError(f"Recipe file not found: {value}")
    return path


def prepare(recipe_path, directory):
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise ToolError("Recipe root must be a directory")
    try:
        recipe = json.loads(file_path(recipe_path).read_text())
    except ValueError as exc:
        raise ToolError(f"Invalid recipe JSON: {exc}") from exc
    rules = recipe.get("changes")
    if recipe.get("version") != 1 or not isinstance(rules, list) or not 1 <= len(rules) <= 1000:
        raise ToolError("Recipe needs version=1 and 1..1000 changes")
    originals, modified = {}, {}
    summaries = []
    total = 0
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ToolError("Each recipe change must be an object")
        relative = rule.get("path")
        path = _path(root, relative)
        if relative not in originals:
            size = path.stat().st_size
            total += size
            if size > 128 * 1024 ** 2 or total > 256 * 1024 ** 2:
                raise ToolError("Recipe edits exceed 128 MiB/file or 256 MiB total. Use binary patch for larger files.")
            originals[relative] = modified[relative] = path.read_bytes()
        data = modified[relative]
        if rule.get("sha256") and hashlib.sha256(data).hexdigest() != rule["sha256"]:
            raise ToolError(f"Change {index + 1}: SHA-256 precondition failed for {relative}")
        expected_count = rule.get("expected_matches")
        if type(expected_count) is not int or expected_count < 1:
            raise ToolError(f"Change {index + 1}: expected_matches must be a positive integer")
        kind = rule.get("kind")
        if kind in ("text_replace", "bytes_replace"):
            try:
                if kind == "text_replace":
                    data.decode("utf-8")
                    before, after = rule["find"].encode("utf-8"), rule["replace"].encode("utf-8")
                else:
                    before, after = bytes.fromhex(rule["find"]), bytes.fromhex(rule["replace"])
                    if len(before) != len(after):
                        raise ToolError("Binary replacements must preserve byte length")
            except (KeyError, ValueError, AttributeError) as exc:
                raise ToolError(f"Invalid {kind} rule: {exc}") from exc
            if not before:
                raise ToolError("Recipe search value cannot be empty")
            count = data.count(before)
            result = data.replace(before, after)
        elif kind == "binary_patch":
            try:
                at = int(str(rule["offset"]), 0)
                before, after = bytes.fromhex(rule["find"]), bytes.fromhex(rule["replace"])
            except (KeyError, ValueError, TypeError) as exc:
                raise ToolError(f"Invalid binary patch: {exc}") from exc
            if not before or len(before) != len(after) or at < 0:
                raise ToolError("Binary patch needs a nonnegative offset and equal nonzero byte lengths")
            count = int(data[at:at + len(before)] == before)
            result = data[:at] + after + data[at + len(before):] if count else data
        elif kind == "xml_set_attribute":
            try:
                xml = ET.fromstring(data)
                nodes = xml.findall(rule["xpath"], {"android": ANDROID})
                attr = rule["attribute"]
                attr = "{" + ANDROID + "}" + attr[8:] if attr.startswith("android:") else attr
                if "expected" not in rule or not isinstance(rule["value"], str):
                    raise ToolError("XML rule requires expected (string or null) and value (string)")
                if any(node.get(attr) != rule["expected"] for node in nodes):
                    raise ToolError("XML attribute precondition failed")
                count = len(nodes)
                for node in nodes:
                    node.set(attr, rule["value"])
                result = ET.tostring(xml, encoding="utf-8", xml_declaration=True)
            except (ET.ParseError, KeyError, SyntaxError, TypeError, AttributeError) as exc:
                raise ToolError(f"Invalid XML rule: {exc}") from exc
        else:
            raise ToolError(f"Unsupported recipe kind: {kind}")
        if count != expected_count:
            raise ToolError(f"Change {index + 1}: expected {expected_count} matches, found {count} in {relative}. No output created.")
        modified[relative] = result
        summaries.append({"change": index + 1, "path": relative, "kind": kind, "matches": count})
    changes = []
    for relative, data in modified.items():
        before = originals[relative]
        entry = {"path": relative, "before_sha256": hashlib.sha256(before).hexdigest(),
                 "after_sha256": hashlib.sha256(data).hexdigest(), "before_bytes": len(before), "after_bytes": len(data)}
        if b"\0" not in before and len(before) < 1024 ** 2:
            entry["diff"] = "".join(difflib.unified_diff(before.decode("utf-8", errors="replace").splitlines(True),
                                                       data.decode("utf-8", errors="replace").splitlines(True),
                                                       fromfile=relative, tofile=relative + " (modified)"))[:16000]
        changes.append(entry)
    return root, modified, {"recipe_version": 1, "rules": summaries, "files": changes,
                             "note": "File edits only. Rebuild and sign decoded APK projects separately."}


def plan(recipe, root):
    return prepare(recipe, root)[2]


def apply(recipe, root, output):
    root, modified, report = prepare(recipe, root)
    output = new_output(output)
    if output.resolve().is_relative_to(root) or root.is_relative_to(output.resolve()):
        raise ToolError("Output must be separate from and outside the input tree")
    # Reject symlinks before copying. Do not follow links to private files outside the project.
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ToolError(f"Input tree contains a symlink: {path.relative_to(root)}")
    if (root / "uat-patch-report.json").exists():
        raise ToolError("Input already contains a patch report; archive/rename it before applying another recipe")
    shutil.copytree(root, output)
    try:
        for relative, data in modified.items():
            target = output / relative
            target.write_bytes(data)
        write_json(output / "uat-patch-report.json", report)
    except Exception:
        shutil.rmtree(output)
        raise
    report["output"] = str(output)
    return report
