"""Bounded Android binary XML reader for manifests; no Android runtime required."""
import struct
import xml.etree.ElementTree as ET

from .common import ToolError

ANDROID = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID)


def _length(data, pos, end, utf8):
    width = 1 if utf8 else 2
    if pos + width > end:
        raise ToolError("Truncated XML string length")
    first = data[pos] if utf8 else struct.unpack_from("<H", data, pos)[0]
    pos += width
    flag = 0x80 if utf8 else 0x8000
    if first & flag:
        if pos + width > end:
            raise ToolError("Truncated XML string length")
        second = data[pos] if utf8 else struct.unpack_from("<H", data, pos)[0]
        first = ((first & (flag - 1)) << (8 if utf8 else 16)) | second
        pos += width
    return first, pos


def _pool(data, start, header, size):
    if header < 28:
        raise ToolError("Invalid XML string pool")
    count, styles, flags, strings_start, styles_start = struct.unpack_from("<5I", data, start + 8)
    if count > 1000000 or start + header + (count + styles) * 4 > start + size:
        raise ToolError("Invalid XML string offsets")
    if strings_start < header + (count + styles) * 4 or strings_start > size:
        raise ToolError("Invalid XML string data")
    end = start + (styles_start or size)
    if end > start + size or end < start + strings_start:
        raise ToolError("Invalid XML style data")
    utf8 = bool(flags & 0x100)
    result = []
    for index in range(count):
        offset = struct.unpack_from("<I", data, start + header + index * 4)[0]
        pos = start + strings_start + offset
        if pos < start + strings_start or pos >= end:
            raise ToolError("Invalid XML string offset")
        length, pos = _length(data, pos, end, utf8)
        if utf8:
            length, pos = _length(data, pos, end, True)
        else:
            length *= 2
        if pos + length > end:
            raise ToolError("Truncated XML string")
        result.append(data[pos:pos + length].decode("utf-8" if utf8 else "utf-16-le", errors="replace"))
    return result


def parse_manifest(data):
    if len(data) > 16 * 1024 * 1024:
        raise ToolError("Manifest exceeds 16 MiB limit")
    if data.lstrip().startswith(b"<"):
        try:
            return ET.fromstring(data)
        except ET.ParseError as exc:
            raise ToolError(f"Invalid manifest XML: {exc}") from exc
    if len(data) < 8:
        raise ToolError("Truncated binary XML")
    kind, header, total = struct.unpack_from("<HHI", data)
    if kind != 3 or header < 8 or total > len(data) or total < header:
        raise ToolError("Invalid Android binary XML header")
    strings = []
    stack = []
    root = None

    def string(index):
        if index == 0xFFFFFFFF:
            return ""
        if index >= len(strings):
            raise ToolError("Invalid XML string index")
        return strings[index]

    def qualified(ns, name):
        namespace = string(ns)
        return f"{{{namespace}}}{string(name)}" if namespace else string(name)

    pos = header
    while pos < total:
        if pos + 8 > total:
            raise ToolError("Truncated XML chunk")
        chunk, chunk_header, size = struct.unpack_from("<HHI", data, pos)
        if chunk_header < 8 or size < chunk_header or pos + size > total:
            raise ToolError("Invalid XML chunk size")
        if chunk == 1:
            strings = _pool(data, pos, chunk_header, size)
        elif chunk == 0x0102:
            if chunk_header < 16 or size < chunk_header + 20:
                raise ToolError("Invalid XML element")
            ext = pos + chunk_header
            ns, name, attr_start, attr_size, count = struct.unpack_from("<IIHHH", data, ext)
            if attr_size < 20 or attr_start < 20 or ext + attr_start + count * attr_size > pos + size:
                raise ToolError("Invalid XML attributes")
            attrs = {}
            for index in range(count):
                at = ext + attr_start + index * attr_size
                attr_ns, attr_name, raw = struct.unpack_from("<III", data, at)
                value_size, _, value_type, value = struct.unpack_from("<HBBI", data, at + 12)
                if value_size != 8:
                    raise ToolError("Invalid XML typed value")
                if raw != 0xFFFFFFFF:
                    rendered = string(raw)
                elif value_type == 3:
                    rendered = string(value)
                elif value_type == 0x12:
                    rendered = "true" if value else "false"
                elif value_type == 0x10:
                    rendered = str(value if value < 0x80000000 else value - 0x100000000)
                elif value_type == 1:
                    rendered = f"@0x{value:08x}"
                else:
                    rendered = f"0x{value:08x}"
                attrs[qualified(attr_ns, attr_name)] = rendered
            node = ET.Element(qualified(ns, name), attrs)
            if stack:
                stack[-1].append(node)
            elif root is None:
                root = node
            else:
                raise ToolError("Multiple XML roots")
            stack.append(node)
        elif chunk == 0x0103:
            if chunk_header < 16 or size < chunk_header + 8 or not stack:
                raise ToolError("Unbalanced XML elements")
            ns, name = struct.unpack_from("<II", data, pos + chunk_header)
            if stack[-1].tag != qualified(ns, name):
                raise ToolError("Mismatched XML end element")
            stack.pop()
        pos += size
    if root is None or stack:
        raise ToolError("Incomplete manifest XML")
    return root


def manifest_summary(root):
    def android(node, key):
        return node.get(f"{{{ANDROID}}}{key}") if node is not None else None

    app = root.find("application")
    sdk = root.find("uses-sdk")
    components = []
    if app is not None:
        for node in app:
            if node.tag in ("activity", "activity-alias", "service", "receiver", "provider"):
                components.append({
                    "type": node.tag, "name": android(node, "name"),
                    "exported_declared": android(node, "exported"),
                    "permission": android(node, "permission"),
                    "intent_filters": len(node.findall("intent-filter")),
                })
    return {
        "package": root.get("package"), "version_name": android(root, "versionName"),
        "version_code": android(root, "versionCode"), "split": root.get("split"),
        "min_sdk": android(sdk, "minSdkVersion"), "target_sdk": android(sdk, "targetSdkVersion"),
        "permissions": sorted({android(n, "name") for n in root
                               if n.tag.startswith("uses-permission") and android(n, "name")}),
        "application": {key: android(app, key) for key in
                        ("label", "debuggable", "allowBackup", "usesCleartextTraffic", "extractNativeLibs")},
        "components": components,
        "note": "Resource references are preserved. Exported values are declarations, not inferred runtime policy.",
    }
