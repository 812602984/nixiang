"""生成合成测试样本（APK / IPA），用于验证解析链路。

真实 APK 不便公开传播，这里按 AOSP ResChunk 规范自造一个最小合法 AXML，
再打进 zip 冒充 APK；IPA 同样用 plistlib + 最小 Mach-O 构造。
跑法：python3 tests/make_fixtures.py
"""

from __future__ import annotations

import plistlib
import struct
import zipfile
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_PREFIX = "android"
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

# 已知 android 命名空间属性（其余属性视为无命名空间）
_ANDROID_ATTRS = {
    "name", "exported", "scheme", "host", "authorities", "permission",
    "minSdkVersion", "targetSdkVersion", "versionCode", "versionName",
}


class StringPoolBuilder:
    """把字符串去重并编排成 UTF-8 字符串池。"""

    def __init__(self) -> None:
        self._index: dict[str, int] = {}

    def intern(self, s: str) -> int:
        if s not in self._index:
            self._index[s] = len(self._index)
        return self._index[s]

    def build(self) -> bytes:
        strings = [None] * len(self._index)  # type: list[str | None]
        for s, i in self._index.items():
            strings[i] = s
        assert all(s is not None for s in strings)

        data = bytearray()
        offsets: list[int] = []
        for s in strings:  # type: ignore[union-attr]
            raw = s.encode("utf-8")  # type: ignore[union-attr]
            offsets.append(len(data))
            data += _len8(len(s))  # type: ignore[arg-type]
            data += _len8(len(raw))
            data += raw + b"\x00"

        header_size = 28
        strings_start = header_size + 4 * len(strings)
        chunk_size = strings_start + len(data)

        out = struct.pack("<HHI", 0x0001, header_size, chunk_size)
        out += struct.pack("<III", len(strings), 0, 0x100)  # flags=UTF8
        out += struct.pack("<II", strings_start, 0)
        for off in offsets:
            out += struct.pack("<I", off)
        out += bytes(data)
        return out


def _len8(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    return bytes([0x80 | (n >> 8), n & 0xFF])


def _start_element(name_idx: int, attrs: list[tuple[int, int, int, int]], line: int = 1) -> bytes:
    body = b""
    for ns_idx, attr_name_idx, val_type, val_data in attrs:
        body += struct.pack("<III", ns_idx, attr_name_idx, 0xFFFFFFFF)
        body += struct.pack("<HBB", 8, 0, val_type)
        body += struct.pack("<I", val_data)
    size = 36 + len(body)
    out = struct.pack("<HHI", 0x0102, 16, size)
    out += struct.pack("<II", line, 0xFFFFFFFF)   # lineNumber, comment
    out += struct.pack("<I", 0xFFFFFFFF)          # ns
    out += struct.pack("<I", name_idx)
    out += struct.pack("<HHH", 20, 20, len(attrs))  # attributeStart/size/count
    out += struct.pack("<HHH", 0, 0, 0)           # id/class/style index
    out += body
    return out


def _end_element(name_idx: int, line: int = 1) -> bytes:
    return (
        struct.pack("<HHI", 0x0103, 16, 24)
        + struct.pack("<II", line, 0xFFFFFFFF)
        + struct.pack("<I", 0xFFFFFFFF)
        + struct.pack("<I", name_idx)
    )


def _start_ns(prefix_idx: int, uri_idx: int, line: int = 1) -> bytes:
    return (
        struct.pack("<HHI", 0x0100, 16, 24)
        + struct.pack("<II", line, 0xFFFFFFFF)
        + struct.pack("<II", prefix_idx, uri_idx)
    )


def build_axml(spec: dict) -> bytes:
    """spec = {"tag":..., "attrs": {name: value}, "children": [...]}"""
    pool = StringPoolBuilder()
    pool.intern(ANDROID_PREFIX)
    pool.intern(ANDROID_NS)

    chunks: list[bytes] = []

    def walk(node: dict, is_root: bool = False) -> None:
        if is_root:
            chunks.append(_start_ns(pool.intern(ANDROID_PREFIX), pool.intern(ANDROID_NS)))

        tag_idx = pool.intern(node["tag"])
        attrs: list[tuple[int, int, int, int]] = []
        for k, v in node.get("attrs", {}).items():
            ns_idx = pool.intern(ANDROID_NS) if k in _ANDROID_ATTRS else 0xFFFFFFFF
            name_idx = pool.intern(k)
            if isinstance(v, bool):
                attrs.append((ns_idx, name_idx, TYPE_INT_BOOLEAN, 1 if v else 0))
            elif isinstance(v, int):
                attrs.append((ns_idx, name_idx, TYPE_INT_DEC, v))
            else:
                attrs.append((ns_idx, name_idx, TYPE_STRING, pool.intern(str(v))))

        chunks.append(_start_element(tag_idx, attrs))
        for child in node.get("children", []):
            walk(child)
        chunks.append(_end_element(tag_idx))

    walk(spec, is_root=True)

    body = b"".join(chunks)
    string_pool = pool.build()
    total = 8 + len(string_pool) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + string_pool + body


def _minimal_macho(extra_payload: bytes = b"") -> bytes:
    """构造一个 64 位 Mach-O，含 LC_ENCRYPTION_INFO_64(cryptid=0)。"""
    header = struct.pack(
        "<IIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0
    ) + struct.pack("<I", 0)
    load_cmd = struct.pack("<IIIIII", 0x2C, 24, 0, 0, 0, 0)
    return header + load_cmd + extra_payload


def make_apk(out_dir: Path) -> Path:
    manifest_spec = {
        "tag": "manifest",
        "attrs": {"package": "com.example.demoapp", "versionName": "2.3.1", "versionCode": 231},
        "children": [
            {"tag": "uses-sdk", "attrs": {"minSdkVersion": 24, "targetSdkVersion": 34}},
            {"tag": "uses-permission", "attrs": {"name": "android.permission.INTERNET"}},
            {"tag": "uses-permission", "attrs": {"name": "android.permission.ACCESS_FINE_LOCATION"}},
            {"tag": "uses-permission", "attrs": {"name": "android.permission.READ_CONTACTS"}},
            {"tag": "uses-permission", "attrs": {"name": "android.permission.READ_PHONE_STATE"}},
            {"tag": "uses-permission", "attrs": {"name": "android.permission.QUERY_ALL_PACKAGES"}},
            {
                "tag": "application",
                "attrs": {"name": "com.example.demoapp.App"},
                "children": [
                    {
                        "tag": "activity",
                        "attrs": {"name": "com.example.demoapp.MainActivity", "exported": True},
                        "children": [
                            {
                                "tag": "intent-filter",
                                "children": [
                                    {"tag": "action", "attrs": {"name": "android.intent.action.VIEW"}},
                                    {"tag": "category", "attrs": {"name": "android.intent.category.DEFAULT"}},
                                    {"tag": "data", "attrs": {"scheme": "demoapp"}},
                                    {"tag": "data", "attrs": {"scheme": "demoscheme"}},
                                ],
                            }
                        ],
                    },
                    {
                        "tag": "provider",
                        "attrs": {"name": "com.example.demoapp.FileProvider", "authorities": "com.example.demoapp.file"},
                    },
                ],
            },
        ],
    }

    fake_dex = (
        b"dex\n035\x00" + b"\x00" * 64
        + b"Lcom/umeng/analytics/MobclickAgent;" + b"\x00" * 8
        + b"Lcom/tencent/mm/opensdk/openapi/WXApi;" + b"\x00" * 8
        + b"Lcom/sensorsdata/analytics/SensorsDataAPI;" + b"\x00" * 8
        + b"Lcom/bytedance/sdk/openadsdk/TTAdSdk;" + b"\x00" * 8
        + b"Lcom/bangcle/protect/ProtectManager;" + b"\x00" * 8
    )

    path = out_dir / "demo-app.apk"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", build_axml(manifest_spec))
        z.writestr("classes.dex", fake_dex)
        z.writestr("classes2.dex", b"dex\n035\x00" + b"\x00" * 200)
        z.writestr("resources.arsc", b"\x00" * 100)
        z.writestr("lib/armeabi-v7a/libjiagu.so", b"\x00" * 64)
    return path


def make_ipa(out_dir: Path) -> Path:
    info = {
        "CFBundleIdentifier": "com.example.iosdemo",
        "CFBundleShortVersionString": "1.4.0",
        "CFBundleVersion": "140",
        "CFBundleExecutable": "IosDemo",
        "CFBundleDisplayName": "演示 App",
        "MinimumOSVersion": "13.0",
        "NSContactsUsageDescription": "用于邀请好友",
        "NSCameraUsageDescription": "用于扫描二维码",
        "NSLocationWhenInUseUsageDescription": "用于展示附近门店",
        "NSUserTrackingUsageDescription": "用于个性化广告推荐",
        "UIBackgroundModes": ["fetch", "remote-notification"],
        "CFBundleURLTypes": [
            {"CFBundleURLSchemes": ["iosdemo", "iosdemo-callback"]}
        ],
    }

    exe_bytes = _minimal_macho(b"WeChatSDK" + b"\x00" * 16 + b"UMengAnalytics" + b"\x00" * 16)

    path = out_dir / "demo-app.ipa"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Payload/IosDemo.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        z.writestr("Payload/IosDemo.app/IosDemo", exe_bytes)
        z.writestr(
            "Payload/IosDemo.app/Frameworks/WeChatSDK.framework/WeChatSDK",
            _minimal_macho(b"WXApi"),
        )
        z.writestr(
            "Payload/IosDemo.app/Frameworks/UMengCommon.framework/UMengCommon",
            _minimal_macho(b"UMeng"),
        )
    return path


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "samples"
    out.mkdir(exist_ok=True)
    print(f"生成 {make_apk(out)}")
    print(f"生成 {make_ipa(out)}")
