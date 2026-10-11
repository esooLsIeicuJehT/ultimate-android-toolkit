#!/usr/bin/env python3
"""Fetch a pinned compiled APK fixture from Apktool's Apache-2.0 test suite."""
import hashlib
import sys
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/iBotPeaches/Apktool/v3.0.3/brut.apktool/apktool-lib/src/test/resources/dynamic_dex/dynamic_dex.apk"
SHA256 = "293f56216e80d7d0bd118138a521c4b4513c43a025bd517447ab3e40d553113f"

path = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/uat-sample.apk")
if path.exists():
    raise SystemExit("Output already exists")
with urllib.request.urlopen(URL, timeout=30) as response:
    data = response.read(1024 * 1024)
if hashlib.sha256(data).hexdigest() != SHA256:
    raise SystemExit("Fixture checksum mismatch")
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(data)
print(path)
