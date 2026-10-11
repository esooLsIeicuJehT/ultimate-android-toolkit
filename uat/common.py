import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


class ToolError(Exception):
    """An actionable error that does not need a traceback."""


def file_path(value):
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise ToolError(f"File not found: {path}")
    return path


def new_output(value):
    path = Path(value).expanduser().absolute()
    if path.exists() or path.is_symlink():
        raise ToolError(f"Output already exists: {path}. Choose a new output path.")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    path = new_output(path)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return path


def emit(value, output=None):
    if output:
        write_json(output, value)
        print(f"Saved: {output}")
    else:
        print(json.dumps(value, indent=2, ensure_ascii=False))


def executable(name):
    found = shutil.which(name)
    if not found:
        raise ToolError(f"Missing tool: {name}. Run ./install-termux.sh or uat doctor.")
    return found


def run(argv, *, capture=False, env=None, timeout=None, cwd=None):
    """Argument arrays only. Never interpolate app names or paths into a shell."""
    try:
        result = subprocess.run(
            [str(x) for x in argv], text=True, capture_output=capture,
            env=env, timeout=timeout, cwd=cwd, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"Could not run {Path(str(argv[0])).name}: {exc}") from exc
    if result.returncode:
        detail = ((result.stderr or result.stdout or "").strip()[-3000:]
                  if capture else "See the tool output above.")
        raise ToolError(f"{Path(str(argv[0])).name} failed ({result.returncode}). {detail}")
    return result.stdout if capture else result


def private_env(**values):
    env = os.environ.copy()
    env.update(values)
    return env
