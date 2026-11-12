"""报告输出：CSV 明细 + Markdown 评估报告。"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

_LEVEL_CN = {"high": "高", "medium": "中", "low": "低"}
_RISK_CN = {"high": "高", "medium": "中", "low": "低"}


def _esc(text: Any) -> str:
    """Markdown 表格里转义竖线。"""
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_csv(results: list[dict[str, Any]], out_path: str | Path) -> Path:
    """把每个文件的权限/SDK/加固项拉平成一张明细表。"""
    out_path = Path(out_path)
    rows: list[dict[str, str]] = []

    for r in results:
        base = {"文件": r["file"], "应用标识": r["app"].get("package", ""), "版本": r["app"].get("version_name", "")}
        for p in r["permissions"]:
            rows.append({**base, "类别": "权限", "名称": p["name"], "分级": _LEVEL_CN.get(p["level"], p["level"]), "说明": p.get("label", ""), "证据/描述": p.get("description", "")})
        for s in r["sdks"]:
            rows.append({**base, "类别": "第三方SDK", "名称": s["name"], "分级": _RISK_CN.get(s["risk"], s["risk"]), "说明": f"{s['vendor']} / {s['category']}", "证据/描述": s["evidence"]})
        for k in r["packers"]:
            rows.append({**base, "类别": "加固", "名称": k["name"], "分级": "—", "说明": k["vendor"], "证据/描述": k["evidence"]})
        for scheme in r["url_schemes"]:
            rows.append({**base, "类别": "URL Scheme", "名称": scheme, "分级": "—", "说明": "对外可唤起", "证据/描述": ""})

    fields = ["文件", "应用标识", "版本", "类别", "名称", "分级", "说明", "证据/描述"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return out_path


def to_markdown(result: dict[str, Any], out_path: str | Path) -> Path:
    """生成单应用的可读评估报告。"""
    out_path = Path(out_path)
    app = result["app"]
    perms = result["permissions"]
    sdks = result["sdks"]
    packers = result["packers"]
    stats = result["stats"]

    high_perms = [p for p in perms if p["level"] == "high"]
    high_sdks = [s for s in sdks if s["risk"] == "high"]

    lines: list[str] = []
    lines.append(f"# App 隐私合规检测报告：{_esc(result['file'])}\n")
    lines.append(f"> 生成时间：{__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}　|　工具：privacy-scanner（静态检测）\n")

    # 一、基本信息
    lines.append("## 一、基本信息\n")
    lines.append("| 项目 | 值 |")
    lines.append("| ---- | ---- |")
    lines.append(f"| 文件 | {_esc(result['file'])} |")
    lines.append(f"| 格式 | {result['format'].upper()} |")
    lines.append(f"| 包名 / Bundle ID | {_esc(app.get('package', '—'))} |")
    lines.append(f"| 版本 | {_esc(app.get('version_name', '—'))} ({_esc(app.get('version_code', ''))}) |")
    size_bytes = result.get("size_bytes") or int(result.get("size_mb", 0) * 1024 * 1024)
    if size_bytes >= 1024 * 1024:
        size_text = f"{size_bytes / 1024 / 1024:.2f} MB"
    elif size_bytes >= 1024:
        size_text = f"{size_bytes / 1024:.1f} KB"
    else:
        size_text = f"{size_bytes} B"
    lines.append(f"| 体积 | {size_text} |")
    if result["format"] == "apk":
        lines.append(f"| dex 数量 | {stats.get('dex_count', '—')} |")
        lines.append(f"| native 库数量 | {stats.get('native_lib_count', '—')} |")
    else:
        lines.append(f"| 内嵌 Framework | {stats.get('framework_count', '—')} |")
        lines.append(f"| 二进制加密状态 | {_esc(stats.get('encryption', '—'))} |")
    lines.append(f"| 最低系统版本 | {_esc(app.get('min_sdk') or app.get('min_os') or '—')} |")
    lines.append("")

    # 二、结论摘要
    lines.append("## 二、结论摘要\n")
    lines.append(f"- 声明权限/隐私用途共 **{len(perms)}** 项，其中高风险 **{len(high_perms)}** 项")
    lines.append(f"- 识别第三方 SDK **{len(sdks)}** 个，其中高风险（涉设备标识/广告归因）**{len(high_sdks)}** 个")
    lines.append(f"- 加固状态：**{('、'.join(k['name'] for k in packers) if packers else '未识别到已知加固')}**")
    lines.append(f"- 对外 URL Scheme **{len(result['url_schemes'])}** 个，导出组件 **{len(result['exported_components'])}** 个")
    lines.append("")

    # 三、权限清单
    lines.append("## 三、权限与隐私用途清单\n")
    if perms:
        lines.append("| 分级 | 权限 / 用途键 | 含义 | 备注 |")
        lines.append("| ---- | ---- | ---- | ---- |")
        for p in perms:
            note = p.get("description", "")
            lines.append(f"| {_LEVEL_CN.get(p['level'], p['level'])} | `{_esc(p['name'])}` | {_esc(p.get('label', ''))} | {_esc(note)} |")
    else:
        lines.append("未声明权限（或解析失败）。")
    lines.append("")

    # 四、SDK 清单
    lines.append("## 四、第三方 SDK 清单\n")
    if sdks:
        lines.append("| 风险 | SDK | 厂商 | 用途 | 命中证据 |")
        lines.append("| ---- | ---- | ---- | ---- | ---- |")
        for s in sdks:
            lines.append(f"| {_RISK_CN.get(s['risk'], s['risk'])} | {_esc(s['name'])} | {_esc(s['vendor'])} | {_esc(s['category'])} | `{_esc(s['evidence'])}` |")
        lines.append("")
        lines.append("> 说明：SDK 命中基于字符串/文件特征，可能存在误报（如仅引用未集成、或类名巧合）。高风险 SDK 通常涉及设备标识符采集，是隐私合规核查重点。")
    else:
        lines.append("未识别到已知第三方 SDK。")
    lines.append("")

    # 五、攻击面
    lines.append("## 五、对外暴露面（安全视角）\n")
    if result["url_schemes"]:
        lines.append("**URL Scheme**（可被其他 App 唤起，注意参数校验与越权风险）：\n")
        for s in result["url_schemes"]:
            lines.append(f"- `{_esc(s)}`")
        lines.append("")
    if result["exported_components"]:
        lines.append("**导出组件**（其他 App 可直接调用，需检查权限保护）：\n")
        lines.append("| 类型 | 组件名 | 含 intent-filter | 保护权限 |")
        lines.append("| ---- | ---- | ---- | ---- |")
        for c in result["exported_components"][:20]:
            lines.append(f"| {c['type']} | `{_esc(c['name'])}` | {'是' if c['has_intent_filter'] else '否'} | {_esc(c.get('permission') or '无')} |")
        lines.append("")
    if not result["url_schemes"] and not result["exported_components"]:
        lines.append("未发现明显对外暴露面。")
    lines.append("")

    # 六、合规风险提示
    lines.append("## 六、合规风险提示与人工复核点\n")
    lines.append("1. **告知一致性**：高风险权限/SDK 是否在隐私政策中逐项列明（含 SDK 名称、收集的信息类型、使用目的）。")
    lines.append("2. **调用时机**：静态检测只能看到\"声明了什么\"，无法证明\"是否在用户同意隐私政策之前调用\"——这一项必须用动态 hook 验证（Frida 监控敏感 API 首次调用时间戳 vs 隐私弹窗确认时间）。")
    lines.append("3. **最小必要**：与业务功能无关的高风险权限（如工具类 App 申请通讯录）属于典型违规点。")
    lines.append("4. **SDK 合规**：高风险 SDK（广告归因、设备指纹类）需确认是否提供关闭选项、是否采集 OAID/IDFA 等设备标识。")
    if result["format"] == "ipa":
        lines.append("5. **ATT 授权**：若存在 `NSUserTrackingUsageDescription`，需核查是否弹出 ATT 授权、是否在用户拒绝后仍做跨 App 追踪。")
    lines.append("")

    # 七、方法与局限
    lines.append("## 七、检测方法与局限\n")
    lines.append("- 静态解析：APK 侧解析二进制 AndroidManifest（AXML）提取权限/组件/Scheme；IPA 侧解析 Info.plist 与 Mach-O 加密标志。")
    lines.append("- 特征匹配：基于内置 SDK 特征库对 dex 字符串、native 库、Framework 名称做子串匹配。")
    lines.append("- **局限**：静态结果不代表实际运行行为。加固应用（已识别到壳）的 dex 字符串可能被加密，特征命中率会下降，需先脱壳再扫描；建议配合动态 hook 出最终结论。")

    if result.get("notes"):
        lines.append("")
        lines.append("**解析备注**：")
        for n in result["notes"]:
            lines.append(f"- {n}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
