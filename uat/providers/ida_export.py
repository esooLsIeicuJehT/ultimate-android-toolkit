"""Run inside licensed IDA with: idat64 -A -S"ida_export.py report.json 500" target.so"""
import json
import os

import ida_auto
import ida_funcs
import ida_lines
import ida_nalt
import idaapi
import idautils
import idc

ida_auto.auto_wait()
destination = idc.ARGV[1]
limit = int(idc.ARGV[2]) if len(idc.ARGV) > 2 else 500
decompiler = None
try:
    import ida_hexrays
    if ida_hexrays.init_hexrays_plugin():
        decompiler = ida_hexrays
except ImportError:
    pass

report = {"provider": "ida", "input": ida_nalt.get_input_file_path(),
          "decompiler_available": decompiler is not None, "functions": [], "strings": []}
functions = list(idautils.Functions())
report["functions_total"] = len(functions)
for ea in functions[:limit]:
    function = ida_funcs.get_func(ea)
    item = {"name": idc.get_func_name(ea), "address": hex(ea), "end": hex(function.end_ea),
            "callers": [], "assembly": []}
    for reference in idautils.XrefsTo(ea):
        item["callers"].append({"address": hex(reference.frm), "function": idc.get_func_name(reference.frm), "type": reference.type})
        if len(item["callers"]) >= 1000:
            break
    for address in idautils.FuncItems(ea):
        line = idc.generate_disasm_line(address, 0)
        if line:
            item["assembly"].append({"address": hex(address), "text": ida_lines.tag_remove(line)})
        if len(item["assembly"]) >= 200:
            break
    if decompiler:
        try:
            code = decompiler.decompile(ea)
            item["pseudocode"] = str(code) if code else None
        except Exception as error:
            item["decompilation_error"] = str(error)
    report["functions"].append(item)
for index, string in enumerate(idautils.Strings()):
    if index >= min(50000, limit * 20):
        break
    report["strings"].append({"address": hex(string.ea), "text": str(string)})
report["functions_truncated"] = len(functions) > limit
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(report, stream, indent=2, ensure_ascii=False)
idc.qexit(0)
