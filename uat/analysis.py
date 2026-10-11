"""One-command static triage with report files and optional source decoding."""
import json
import shutil
from pathlib import Path

from . import apk, binary, external, search
from .common import ToolError, file_path, new_output, write_json


def analyze(path, output, decode=False, java=False):
    path, output = file_path(path), new_output(output)
    report = apk.inspect(path, hashes=True)
    output.mkdir(mode=0o700)
    shutil.copyfile(path, output / "input.apk")
    extracted = output / "extracted"
    apk.extract(path, extracted)
    report["dex_reports"] = []
    for name in report["dex_files"]:
        try:
            value = binary.dex_info(extracted / name, 500)
        except ToolError as exc:
            value = {"error": str(exc)}
        report["dex_reports"].append({"entry": name, "report": value})
    report["native_reports"] = []
    for name in report["native_libraries"]:
        report["native_reports"].append({"entry": name, "report": binary.info(extracted / name)})
    if decode:
        print("Decoding resources and smali...")
        external.decode(path, output / "decoded")
    if java:
        print("Decompiling approximate Java...")
        external.decompile(path, output / "java")
    report["search_results"] = {}
    for preset in search.PRESETS:
        report["search_results"][preset] = search.search(extracted, preset=preset, limit=200)
    write_json(output / "analysis.json", report)
    return {"output": str(output), "report": str(output / "analysis.json"),
            "engine_hints": report["engine_hints"], "dex_files": len(report["dex_files"]),
            "native_libraries": len(report["native_libraries"]),
            "search_hits": {key: len(value["hits"]) for key, value in report["search_results"].items()},
            "note": "Static heuristics help navigation. They do not infer safe game-function patches."}
