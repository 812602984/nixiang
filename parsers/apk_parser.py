"""APK 解析：Manifest（AXML）+ dex 字符串特征 + 文件路径特征。"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

from .axml import ANDROID_NS, Node, parse_axml  # noqa: F401

_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def load_rules() -> dict[str, Any]:
    sdk_rules = json.loads((_RULES_DIR / "sdk_rules.json").read_text(encoding="utf-8"))
    perm_rules = json.loads((_RULES_DIR / "permissions.json").read_text(encoding="utf-8"))
    return {"sdk": sdk_rules, "perm": perm_rules}


def _read_manifest(z: zipfile.ZipFile) -> Node:
    """读取并解析 AndroidManifest.xml，兼容二进制与明文两种格式。"""
    raw = z.read("AndroidManifest.xml")
    if raw.lstrip().startswith(b"<"):
        # 极少数调试包是明文 XML
        import xml.etree.ElementTree as ET

        root = ET.fromstring(raw)
        node = Node(root.tag)
        for k, v in root.attrib.items():
            node.attrs[k.split("}")[-1]] = v
            node.ns_attrs[k.split("}")[-1]] = v
        for child in root.iter():
            if child is root:
                continue
            cnode = Node(child.tag, parent=node)
            node.children.append(cnode)
            for k, v in child.attrib.items():
                cnode.attrs[k.split("}")[-1]] = v
                cnode.ns_attrs[k.split("}")[-1]] = v
        return node
    return parse_axml(raw)


def _scan_blob(blob: bytes, patterns: list[str]) -> str | None:
    """在字节流里搜特征，返回命中的第一个 pattern。"""
    for p in patterns:
        try:
            if p.encode("utf-8") in blob or p.replace(".", "/").encode("utf-8") in blob:
                return p
        except (UnicodeEncodeError, ValueError):
            continue
    return None


def _extract_schemes(app: Node) -> list[str]:
    schemes: list[str] = []
    for data_node in app.find_all("data"):
        scheme = data_node.get("scheme")
        if scheme and scheme.lower() != "http" and scheme.lower() != "https":
            if scheme not in schemes:
                schemes.append(scheme)
    return schemes


def _extract_components(app: Node) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for node in app.find_all(tag):
            name = node.get("name") or ""
            exported_attr = node.get("exported")
            has_filter = node.find("intent-filter") is not None
            # 未显式声明 exported 时，含 intent-filter 的组件默认对外暴露（API<31）
            exported = (exported_attr == "true") or (exported_attr is None and has_filter)
            if exported:
                out.append(
                    {
                        "type": tag,
                        "name": name,
                        "exported": True,
                        "has_intent_filter": has_filter,
                        "permission": node.get("permission"),
                    }
                )
    return out


def parse_apk(path: str | Path, max_scan_bytes: int = 128 * 1024 * 1024) -> dict[str, Any]:
    path = Path(path)
    rules = load_rules()
    sdk_defs = rules["sdk"]["sdks"]
    packer_defs = rules["sdk"]["packers"]
    perm_defs = rules["perm"]["android_permissions"]

    size_bytes = path.stat().st_size
    result: dict[str, Any] = {
        "file": path.name,
        "path": str(path),
        "format": "apk",
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
        doc = _read_manifest(z)
        # parse_axml 返回虚拟 <document>，真正的根元素是 <manifest>
        manifest = doc.find("manifest") or doc
        app_node = manifest.find("application")

        # --- 基础信息 ---
        result["app"] = {
            "package": manifest.get("package") or "",
            "version_name": manifest.get("versionName") or "",
            "version_code": manifest.get("versionCode") or "",
        }
        uses_sdk = manifest.find("uses-sdk")
        if uses_sdk:
            result["app"]["min_sdk"] = uses_sdk.get("minSdkVersion") or ""
            result["app"]["target_sdk"] = uses_sdk.get("targetSdkVersion") or ""

        # --- 权限（带分级） ---
        perms: list[dict[str, Any]] = []
        for node in manifest.find_all("uses-permission"):
            name = (node.get("name") or "").split(".")[-1]
            meta = perm_defs.get(name, {})
            perms.append(
                {
                    "name": node.get("name") or "",
                    "short": name,
                    "level": meta.get("level", "low"),
                    "label": meta.get("label", "未分类"),
                }
            )
        # 按风险排序：high > medium > low
        order = {"high": 0, "medium": 1, "low": 2}
        perms.sort(key=lambda x: order.get(x["level"], 3))
        result["permissions"] = perms

        # --- 组件与 URL Scheme ---
        if app_node is not None:
            result["url_schemes"] = _extract_schemes(app_node)
            result["exported_components"] = _extract_components(app_node)

        # --- 特征扫描：dex 字符串 + 文件路径 ---
        dex_names = [n for n in names if re.match(r"classes\d*\.dex", n)]
        native_libs = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
        result["stats"] = {
            "dex_count": len(dex_names),
            "native_lib_count": len(native_libs),
            "file_count": len(names),
        }

        evidence_blobs: list[tuple[str, bytes]] = []
        budget = max_scan_bytes
        for n in dex_names:
            if budget <= 0:
                result["notes"].append("dex 扫描超出上限，部分文件已跳过")
                break
            data = z.read(n)
            budget -= len(data)
            evidence_blobs.append((n, data))

        # 文件名与 so 名也作为证据（加固常见于 lib 目录）
        names_blob = "\n".join(names).encode("utf-8", errors="ignore")
        evidence_blobs.append(("zip-entry-list", names_blob))

        for sdk in sdk_defs:
            hit = None
            where = ""
            for label, blob in evidence_blobs:
                h = _scan_blob(blob, sdk["patterns"])
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
            hit = None
            where = ""
            for label, blob in evidence_blobs:
                h = _scan_blob(blob, packer["patterns"])
                if h:
                    hit, where = h, label
                    break
            if hit:
                result["packers"].append(
                    {
                        "name": packer["name"],
                        "vendor": packer["vendor"],
                        "evidence": f"{where}: {hit}",
                    }
                )

    if not result["packers"]:
        result["notes"].append("未识别到已知加固特征（可能是未加固、或使用了新的加固方案）")

    return result
