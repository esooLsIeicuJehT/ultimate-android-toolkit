import getpass
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .common import ToolError, executable, file_path, new_output, private_env, run, sha256


def password(variable=None, prompt="Keystore password: ", confirm=False):
    if variable:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable) or variable not in os.environ:
            raise ToolError("Password environment variable is invalid or unset")
        value = os.environ[variable]
    else:
        if not __import__("sys").stdin.isatty():
            raise ToolError("No interactive terminal. Set a password environment variable and use --password-env NAME.")
        value = getpass.getpass(prompt)
        if confirm and value != getpass.getpass("Confirm password: "):
            raise ToolError("Passwords do not match")
    if not value:
        raise ToolError("Empty keystore passwords are unsupported")
    return value


def create_key(path, alias="uat", password_env=None, dname="CN=Android Toolkit, OU=Development, O=Local, C=US"):
    path = new_output(path)
    secret = password(password_env, confirm=True)
    if len(secret) < 6:
        raise ToolError("Keystore password must contain at least six characters")
    env = private_env(UAT_STORE_PASS=secret)
    with tempfile.TemporaryDirectory(prefix="uat-key-", dir=path.parent) as directory:
        temp = Path(directory) / "key.p12"
        run([executable("keytool"), "-genkeypair", "-noprompt", "-keystore", temp,
             "-storetype", "PKCS12", "-alias", alias, "-keyalg", "RSA", "-keysize", "3072",
             "-validity", "10000", "-dname", dname, "-storepass:env", "UAT_STORE_PASS",
             "-keypass:env", "UAT_STORE_PASS"], env=env)
        with temp.open("rb") as source, path.open("xb") as target:
            os.chmod(path, 0o600)
            shutil.copyfileobj(source, target)
    return {"keystore": str(path), "alias": alias, "type": "PKCS12",
            "note": "Keep this file and password. Reuse the same key to update your signed builds."}


def key_info(path, password_env=None):
    secret = password(password_env)
    return run([executable("keytool"), "-list", "-v", "-keystore", file_path(path),
                "-storepass:env", "UAT_STORE_PASS"], capture=True, env=private_env(UAT_STORE_PASS=secret))


def verify(path, min_sdk=None):
    argv = [executable("apksigner"), "verify", "--verbose", "--print-certs"]
    if min_sdk:
        argv += ["--min-sdk-version", str(min_sdk)]
    return run(argv + [file_path(path)], capture=True)


def _alignment_args(tool, check=False):
    help_result = subprocess.run([tool, "-h"], capture_output=True, text=True)
    help_text = (help_result.stdout or "") + (help_result.stderr or "")
    page_args = ["-P", "16"] if "-P" in help_text else ["-p"]
    return (["-c"] if check else ["-f"]) + page_args + ["4"]


def align(path, output):
    path, output = file_path(path), new_output(output)
    tool = executable("zipalign")
    run([tool] + _alignment_args(tool) + [path, output])
    run([tool] + _alignment_args(tool, True) + [output])
    return {"output": str(output), "note": "Alignment changes invalidate existing signatures. Sign this output next."}


def sign(path, output, keystore, alias="uat", password_env=None, key_password_env=None, min_sdk=None, _secrets=None):
    path, output, keystore = file_path(path), new_output(output), file_path(keystore)
    if _secrets is None:
        secret = password(password_env)
        key_secret = password(key_password_env, "Key password: ") if key_password_env else secret
    else:
        secret, key_secret = _secrets
    signer, aligner = executable("apksigner"), executable("zipalign")
    with tempfile.TemporaryDirectory(prefix="uat-sign-", dir=output.parent) as directory:
        aligned = Path(directory) / "aligned.apk"
        signed = Path(directory) / "signed.apk"
        run([aligner] + _alignment_args(aligner) + [path, aligned])
        argv = [signer, "sign", "--ks", keystore, "--ks-key-alias", alias,
                "--ks-pass", "env:UAT_STORE_PASS", "--key-pass", "env:UAT_KEY_PASS",
                "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                "--v3-signing-enabled", "true", "--v4-signing-enabled", "false", "--out", signed]
        if min_sdk:
            argv += ["--min-sdk-version", str(min_sdk)]
        run(argv + [aligned], env=private_env(UAT_STORE_PASS=secret, UAT_KEY_PASS=key_secret))
        verification = verify(signed, min_sdk)
        run([aligner] + _alignment_args(aligner, True) + [signed])
        with signed.open("rb") as source, output.open("xb") as target:
            shutil.copyfileobj(source, target, 1024 ** 2)
    return {"output": str(output), "sha256": sha256(output), "verification": verification,
            "alignment": "16 KiB native-library pages" if "-P" in _alignment_args(aligner) else "Legacy 4 KiB pages; upgrade zipalign for 16 KiB devices"}


def sign_set(directory, output, keystore, **options):
    from .apk import open_archive
    root = Path(directory).expanduser().resolve()
    paths = sorted(root.glob("*.apk"))
    if not root.is_dir() or not 1 <= len(paths) <= 100:
        raise ToolError("Signing set requires a directory containing 1..100 APK files")
    for path in paths:
        with open_archive(path):
            pass
    output = new_output(output)
    secret = password(options.get("password_env"))
    key_secret = password(options["key_password_env"], "Key password: ") if options.get("key_password_env") else secret
    output.mkdir(mode=0o700)
    try:
        results = [sign(path, output / path.name, keystore, _secrets=(secret, key_secret), **options) for path in paths]
    except Exception:
        shutil.rmtree(output)
        raise
    return {"output": str(output), "apks": results,
            "note": "All APKs use the same key. This preserves signing consistency; it does not merge or fix incompatible splits."}
