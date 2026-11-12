"""Android 二进制 XML（AXML）解析器 —— 纯标准库实现。

APK 里的 AndroidManifest.xml 是编译过的二进制格式（ResChunk），
不能交给 ElementTree 之类的文本 XML 解析器。本模块按 AOSP 的
ResourceTypes.h 规范手工解析，用于提取包名、权限、组件与 intent-filter。

为什么自己写而不用 androguard：
1. 零第三方依赖，任何机器 clone 下来就能跑（对安全评估工具很重要）；
2. 解析过程完全可控，遇到混淆/畸形 Manifest 时能自己加容错；
3. 解析逻辑完全可审阅、可按需扩展，不受第三方库版本与实现变更影响。
"""

from __future__ import annotations

import struct

# ResChunk 类型
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_TYPE = 0x0003
_RES_XML_START_NAMESPACE_TYPE = 0x0100
_RES_XML_END_NAMESPACE_TYPE = 0x0101
_RES_XML_START_ELEMENT_TYPE = 0x0102
_RES_XML_END_ELEMENT_TYPE = 0x0103
_RES_XML_RESOURCE_MAP_TYPE = 0x0180

# Res_value 数据类型
_TYPE_REFERENCE = 0x01
_TYPE_STRING = 0x03
_TYPE_FLOAT = 0x04
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12

_STRING_POOL_UTF8_FLAG = 0x100

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# 当属性名在字符串池里缺失时（少见，个别加固工具会抹掉），
# 用资源 ID 兜底映射到常见属性名。
_RES_ID_TO_ATTR = {
    0x01010003: "name",
    0x01010006: "permission",
    0x01010010: "exported",
    0x0101001D: "authorities",
    0x01010020: "targetActivity",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x0101021E: "scheme",
    0x0101021F: "host",
}


class Node:
    """XML 元素节点。"""

    __slots__ = ("tag", "attrs", "ns_attrs", "children", "parent", "line")

    def __init__(self, tag: str, line: int = -1, parent: "Node | None" = None):
        self.tag = tag
        self.attrs: dict[str, str] = {}
        self.ns_attrs: dict[str, str] = {}  # 来自 android 命名空间的属性（同名时优先级更高）
        self.children: list[Node] = []
        self.parent = parent
        self.line = line

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<Node {self.tag} {self.attrs}>"

    def get(self, name: str, default: str | None = None) -> str | None:
        """按属性名取值，优先取 android 命名空间。"""
        return self.ns_attrs.get(name, self.attrs.get(name, default))

    def find_all(self, tag: str) -> list["Node"]:
        """深度优先查找同名后代节点。"""
        out: list[Node] = []
        stack = list(self.children)
        while stack:
            cur = stack.pop()
            if cur.tag == tag:
                out.append(cur)
            stack.extend(cur.children)
        return out

    def find(self, tag: str) -> "Node | None":
        found = self.find_all(tag)
        return found[0] if found else None


def _read_chunk_header(data: bytes, offset: int) -> tuple[int, int, int]:
    """返回 (type, header_size, chunk_size)。"""
    if offset + 8 > len(data):
        raise ValueError("AXML 截断：chunk header 越界")
    ctype, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    if chunk_size < 8 or offset + chunk_size > len(data):
        # 畸形文件里 size 可能不准，退回用 header_size 保护
        chunk_size = min(len(data) - offset, max(chunk_size, header_size))
    return ctype, header_size, chunk_size


def _decode_length8(data: bytes, pos: int) -> tuple[int, int]:
    """UTF-8 字符串池里的变长长度字段。"""
    first = data[pos]
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[pos + 1], pos + 2
    return first, pos + 1


def _parse_string_pool(data: bytes, offset: int) -> list[str]:
    """解析 RES_STRING_POOL_TYPE，返回字符串数组。"""
    _, header_size, chunk_size = _read_chunk_header(data, offset)
    string_count, style_count, flags = struct.unpack_from("<III", data, offset + 8)
    strings_start = struct.unpack_from("<I", data, offset + 20)[0]
    is_utf8 = bool(flags & _STRING_POOL_UTF8_FLAG)

    base = offset + strings_start
    offsets: list[int] = []
    for i in range(string_count):
        pos = offset + header_size + i * 4
        if pos + 4 > len(data):
            break
        offsets.append(struct.unpack_from("<I", data, pos)[0])

    strings: list[str] = []
    for rel in offsets:
        pos = base + rel
        try:
            if is_utf8:
                _, pos = _decode_length8(data, pos)  # utf-16 长度，跳过
                length, pos = _decode_length8(data, pos)
                raw = data[pos:pos + length]
                strings.append(raw.decode("utf-8", errors="replace"))
            else:
                length = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                if length & 0x8000:
                    length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                raw = data[pos:pos + length * 2]
                strings.append(raw.decode("utf-16-le", errors="replace"))
        except (IndexError, struct.error):
            strings.append("")
    return strings


def parse_axml(data: bytes) -> Node:
    """把 AXML 字节流解析成节点树，返回虚拟根节点 <document>。"""
    ctype, _, _ = _read_chunk_header(data, 0)
    if ctype != _RES_XML_TYPE:
        raise ValueError(f"不是 AXML 文件（chunk type=0x{ctype:04x}）")

    root = Node("document")
    cur: Node = root
    strings: list[str] = []

    # 顶层头 8 字节之后紧跟子 chunk
    pos = 8
    while pos + 8 <= len(data):
        ctype, header_size, chunk_size = _read_chunk_header(data, pos)

        if ctype == _RES_STRING_POOL_TYPE:
            strings = _parse_string_pool(data, pos)

        elif ctype == _RES_XML_START_ELEMENT_TYPE:
            chunk = pos
            line = struct.unpack_from("<I", data, chunk + 8)[0]
            name_idx = struct.unpack_from("<I", data, chunk + 20)[0]
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, chunk + 24)
            tag = strings[name_idx] if name_idx < len(strings) else f"tag_{name_idx}"

            node = Node(tag, line, cur)
            cur.children.append(node)

            # attributeStart 是相对 ResXMLTree_attrExt（即 chunk+16）的偏移，标准值为 20
            attr_base = chunk + 16 + attr_start
            if attr_base + attr_count * attr_size > chunk + chunk_size:
                attr_base = chunk + attr_start  # 兼容个别非标准生成器

            for i in range(attr_count):
                a = attr_base + i * attr_size
                if a + 20 > len(data):
                    break
                ns_idx, attr_name_idx, raw_idx = struct.unpack_from("<III", data, a)
                val_size, _, val_type = struct.unpack_from("<HBB", data, a + 12)
                val_data = struct.unpack_from("<I", data, a + 16)[0]

                attr_name = strings[attr_name_idx] if attr_name_idx < len(strings) else ""
                if not attr_name:
                    attr_name = _RES_ID_TO_ATTR.get(attr_name_idx, f"attr_0x{attr_name_idx:08x}")

                ns_uri = strings[ns_idx] if ns_idx < len(strings) else ""
                value = _resolve_value(strings, raw_idx, val_type, val_data)
                node.attrs[attr_name] = value
                if ns_uri == ANDROID_NS or not ns_uri:
                    node.ns_attrs[attr_name] = value
            cur = node

        elif ctype == _RES_XML_END_ELEMENT_TYPE:
            if cur.parent is not None:
                cur = cur.parent

        pos += chunk_size

    return root


def _resolve_value(strings: list[str], raw_idx: int, val_type: int, val_data: int) -> str:
    """把 Res_value 还原成可读字符串。"""
    if val_type == _TYPE_STRING:
        return strings[val_data] if val_data < len(strings) else ""
    if val_type == _TYPE_INT_BOOLEAN:
        return "true" if val_data else "false"
    if val_type == _TYPE_INT_DEC:
        return str(val_data)
    if val_type == _TYPE_INT_HEX:
        return hex(val_data)
    if val_type == _TYPE_REFERENCE:
        return f"@0x{val_data:08x}"
    if val_type == _TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", val_data))[0])
    if 0 <= raw_idx < len(strings) and strings[raw_idx]:
        return strings[raw_idx]
    return str(val_data)


if __name__ == "__main__":  # pragma: no cover
    import sys

    with open(sys.argv[1], "rb") as f:
        tree = parse_axml(f.read())
    for node in tree.find_all("uses-permission"):
        print(node.get("name"))
