import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import apk, external, signing
from .common import ToolError, file_path, new_output, sha256


def _time():
    return datetime.now(timezone.utc).isoformat()


def _save(root, data):
    temporary = root / ".project.json.tmp"
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")
    os.replace(temporary, root / "project.json")


def load(directory):
    root = Path(directory).expanduser().resolve()
    try:
        data = json.loads((root / "project.json").read_text())
    except (OSError, ValueError) as exc:
        raise ToolError(f"Invalid toolkit project: {exc}") from exc
    if data.get("schema") != 1:
        raise ToolError("Unsupported project schema")
    if sha256(file_path(root / "original.apk")) != data["original_sha256"]:
        raise ToolError("Project original APK changed. Restore the original before proceeding.")
    return root, data


def create(path, directory):
    path, root = file_path(path), new_output(directory)
    report = apk.inspect(path)
    root.mkdir(mode=0o700)
    shutil.copyfile(path, root / "original.apk")
    os.chmod(root / "original.apk", 0o444)
    data = {"schema": 1, "created_at": _time(), "original_sha256": report["sha256"],
            "source_name": path.name, "manifest": report.get("manifest"),
            "history": [{"at": _time(), "action": "import"}]}
    _save(root, data)
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return {"project": str(root), "original_sha256": data["original_sha256"]}


def decode(directory):
    root, data = load(directory)
    result = external.decode(root / "original.apk", root / "decoded")
    data["history"].append({"at": _time(), "action": "decode"})
    _save(root, data)
    return result


def rebuild(directory, output, keystore=None, **options):
    root, data = load(directory)
    output = new_output(output)
    if keystore:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="uat-build-", dir=root) as temp:
            unsigned = Path(temp) / "unsigned.apk"
            external.build(root / "decoded", unsigned)
            result = signing.sign(unsigned, output, keystore, **options)
    else:
        result = external.build(root / "decoded", output)
    data["history"].append({"at": _time(), "action": "rebuild", "signed": bool(keystore),
                            "output_name": output.name, "sha256": sha256(output)})
    _save(root, data)
    return result
