"""IPA 解析：Info.plist + Frameworks + 主二进制特征 + Mach-O 加密状态。"""

from __future__ import annotations

import plistlib
import struct
import zipfile
from pathlib import Path
from typing import Any

from .apk_parser import load_rules

# Mach-O 常量
_MH_MAGIC_32 = 0xFEEDFACE
_MH_MAGIC_64 = 0xFEEDFACF
_FAT_MAGIC_BE = 0xCAFEBABE
_LC_ENCRYPTION_INFO = 0x21
_LC_ENCRYPTION_INFO_64 = 0x2C


def _parse_thin_macho(data: bytes, base: int) -> dict[str, Any]:
    """解析单个 Mach-O 切片，返回架构与加密状态。"""
    magic = struct.unpack_from("<I", data, base)[0]
    is_64 = magic == _MH_MAGIC_64
    if not is_64 and magic != _MH_MAGIC_32:
        return {"error": f"unknown Mach-O magic 0x{magic:08x}"}

    cputype = struct.unpack_from("<I", data, base + 4)[0]
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    header_size = 32 if is_64 else 28

    cryptid: int | None = None
    pos = base + header_size
    for _ in range(ncmds):
        if pos + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64):
            if pos + 20 <= len(data):
                cryptid = struct.unpack_from("<I", data, pos + 16)[0]
        if cmdsize <= 0:
            break
        pos += cmdsize

    arch = {12: "armv7", 0x0100000C: "arm64", 0x0100000C: "arm64"}.get(cputype, f"0x{cputype:x}")
    return {
        "arch": arch,
        "bits": 64 if is_64 else 32,
        "cryptid": cryptid,
        "encrypted": None if cryptid is None else bool(cryptid),
    }


def inspect_macho(data: bytes) -> dict[str, Any]:
    """解析 Mach-O（thin 或 fat），判断是否被 App Store 加密。"""
    if len(data) < 8:
        return {"error": "file too small"}
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be == _FAT_MAGIC_BE:
        nfat = struct.unpack_from(">I", data, 4)[0]
        slices = []
        for i in range(min(nfat, 8)):
            off = 8 + i * 20
            if off + 20 > len(data):
                break
            cputype, _, slice_off, slice_size, _ = struct.unpack_from(">IIIII", data, off)
            info = _parse_thin_macho(data, slice_off)
            info["cputype_raw"] = cputype
            slices.append(info)
        return {"type": "fat", "slices": slices}
    return {**_parse_thin_macho(data, 0), "type": "thin"}


def _scan_bytes(blob: bytes, patterns: list[str]) -> str | None:
    for p in patterns:
        try:
            if p.encode("utf-8") in blob:
                return p
        except (UnicodeEncodeError, ValueError):
            continue
    return None


def parse_ipa(path: str | Path, max_scan_bytes: int = 128 * 1024 * 1024) -> dict[str, Any]:
    path = Path(path)
    rules = load_rules()
    sdk_defs = rules["sdk"]["sdks"]
    packer_defs = rules["sdk"]["packers"]
    usage_defs = rules["perm"]["ios_usage_keys"]

    size_bytes = path.stat().st_size
    result: dict[str, Any] = {
        "file": path.name,
        "path": str(path),
        "format": "ipa",
        "size_bytes": size_bytes,
        "size_mb": round(size_bytes / 1024 / 1024, 2),
        "app": {},
        "permissions": [],
        "sdks": [],
        "packers": [],
        "url_schemes": [],
        "exported_components": [],
        "stats": {},
        "notes": [],
    }

    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        # 从文件路径推导 .app 目录（zip 里不一定显式存在目录条目）
        app_dirs = sorted(
            {f"Payload/{n.split('/')[1]}/" for n in names if n.startswith("Payload/") and n.count("/") >= 2}
        )
        if not app_dirs:
            raise ValueError("IPA 结构异常：未找到 Payload/*.app/")
        app_dir = app_dirs[0]
        app_name = app_dir[len("Payload/"):-1]

        plist_name = f"{app_dir}Info.plist"
        info = plistlib.loads(z.read(plist_name))

        result["app"] = {
            "package": info.get("CFBundleIdentifier", ""),
            "version_name": info.get("CFBundleShortVersionString", ""),
            "version_code": info.get("CFBundleVersion", ""),
            "min_os": info.get("MinimumOSVersion", ""),
            "display_name": info.get("CFBundleDisplayName") or info.get("CFBundleName", ""),
        }

        # --- 权限用途声明（iOS 的"权限"就是这些 UsageDescription） ---
        perms: list[dict[str, Any]] = []
        for key, value in info.items():
            if key in usage_defs:
                perms.append(
                    {
                        "name": key,
                        "short": key,
                        "level": usage_defs[key]["level"],
                        "label": usage_defs[key]["label"],
                        "description": str(value)[:120],
                    }
                )
            elif key.endswith("UsageDescription"):
                perms.append(
                    {"name": key, "short": key, "level": "medium", "label": "未分类用途声明", "description": str(value)[:120]}
                )
        order = {"high": 0, "medium": 1, "low": 2}
        perms.sort(key=lambda x: order.get(x["level"], 3))
        result["permissions"] = perms

        # --- URL Scheme 与后台模式 ---
        schemes: list[str] = []
        for url_type in info.get("CFBundleURLTypes", []) or []:
            for s in url_type.get("CFBundleURLSchemes", []) or []:
                if s not in schemes:
                    schemes.append(s)
        result["url_schemes"] = schemes
        result["app"]["background_modes"] = info.get("UIBackgroundModes", [])

        # --- 内嵌框架（框架名本身就是 SDK 证据） ---
        fw_prefix = f"{app_dir}Frameworks/"
        frameworks = sorted(
            {
                n[len(fw_prefix):].split("/")[0]
                for n in names
                if n.startswith(fw_prefix) and n[len(fw_prefix):].split("/")[0].endswith(".framework")
            }
        )
        result["stats"] = {"framework_count": len(frameworks), "file_count": len(names)}

        # --- 主二进制与 Mach-O 状态 ---
        exe = info.get("CFBundleExecutable", app_name)
        exe_path = f"{app_dir}{exe}"
        macho_info: dict[str, Any] = {}
        blobs: list[tuple[str, bytes]] = []
        budget = max_scan_bytes
        if exe_path in names:
            with z.open(exe_path) as f:
                data = f.read(budget)
            budget -= len(data)
            macho_info = inspect_macho(data)
            blobs.append((exe_path, data))
        else:
            result["notes"].append("未找到主可执行文件，可能被裁剪或结构异常")

        # 框架二进制也扫一遍（很多 SDK 以 framework 形式存在）
        for fw in frameworks[:5]:
            fw_bin = f"{app_dir}Frameworks/{fw}/{fw[:-len('.framework')]}"
            if fw_bin not in names:
                continue
            with z.open(fw_bin) as f:
                blob = f.read(min(budget, 32 * 1024 * 1024))
            budget -= len(blob)
            blobs.append((fw_bin, blob))

        # Frameworks 名字与 Info.plist 内容作为轻量证据
        blobs.append(("frameworks-list", "\n".join(frameworks).encode("utf-8", errors="ignore")))
        blobs.append(("Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_XML)))

        for sdk in sdk_defs:
            hit, where = None, ""
            for label, blob in blobs:
                h = _scan_bytes(blob, sdk["patterns"])
                if h:
                    hit, where = h, label
                    break
            if hit:
                result["sdks"].append(
                    {
                        "name": sdk["name"],
                        "vendor": sdk["vendor"],
                        "category": sdk["category"],
                        "risk": sdk["risk"],
                        "evidence": f"{where}: {hit}",
                    }
                )

        for packer in packer_defs:
            hit, where = None, ""
            for label, blob in blobs:
                h = _scan_bytes(blob, packer["patterns"])
                if h:
                    hit, where = h, label
                    break
            if hit:
                result["packers"].append(
                    {"name": packer["name"], "vendor": packer["vendor"], "evidence": f"{where}: {hit}"}
                )

        # --- 加密状态 ---
        encryption = "未知"
        if macho_info.get("type") == "fat":
            states = [s.get("encrypted") for s in macho_info.get("slices", [])]
            if any(st is True for st in states):
                encryption = "已加密（App Store 加密，分析前需先脱壳）"
            elif any(st is False for st in states):
                encryption = "未加密（cryptid=0，通常已脱壳或企业签）"
        elif "encrypted" in macho_info:
            encryption = {True: "已加密（App Store 加密，分析前需先脱壳）", False: "未加密（cryptid=0，通常已脱壳或企业签）"}.get(
                macho_info["encrypted"], "未知"
            )
        result["stats"]["macho"] = macho_info
        result["stats"]["encryption"] = encryption

    if not result["packers"]:
        result["notes"].append("未识别到 iOS 加固特征（iOS 侧加固方案较少，多数靠 App Store 加密）")

    return result
