"""privacy-scanner 命令行入口。

用法：
    python3 scanner.py app.apk                # 单文件，生成报告到 ./out
    python3 scanner.py a.apk b.ipa            # 多文件
    python3 scanner.py samples/ --out reports # 扫目录
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from parsers.apk_parser import parse_apk
from parsers.ipa_parser import parse_ipa
from report import to_csv, to_markdown


def collect_targets(inputs: list[str]) -> list[Path]:
    """把命令行参数展开成待扫描文件列表。"""
    targets: list[Path] = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.suffix.lower() in {".apk", ".ipa", ".xapk"}:
                    targets.append(f)
        elif p.is_file():
            targets.append(p)
        else:
            print(f"[跳过] 路径不存在：{item}", file=sys.stderr)
    return targets


def scan_one(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix in {".apk", ".xapk"}:
        return parse_apk(path)
    if suffix == ".ipa":
        return parse_ipa(path)
    raise ValueError(f"不支持的文件类型：{suffix}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="App 隐私合规静态检测（零依赖）")
    parser.add_argument("inputs", nargs="+", help="APK/IPA 文件或目录")
    parser.add_argument("--out", default="out", help="报告输出目录（默认 ./out）")
    parser.add_argument("--json", action="store_true", help="同时输出原始 JSON")
    args = parser.parse_args(argv)

    targets = collect_targets(args.inputs)
    if not targets:
        print("没有找到可扫描的 .apk / .ipa 文件", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []

    for path in targets:
        print(f"[扫描] {path.name}")
        try:
            result = scan_one(path)
        except Exception as e:  # noqa: BLE001 - 单文件失败不该中断整批
            print(f"  [失败] {path.name}: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        results.append(result)
        md_path = to_markdown(result, out_dir / f"{path.stem}-{result['format']}-报告.md")
        if args.json:
            (out_dir / f"{path.stem}-{result['format']}-结果.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        print(
            f"  权限 {len(result['permissions'])} 项 / SDK {len(result['sdks'])} 个 / "
            f"加固 {len(result['packers'])} 个 → {md_path}"
        )

    if results:
        csv_path = to_csv(results, out_dir / "汇总.csv")
        print(f"\n[完成] {len(results)} 个文件，汇总表：{csv_path}")

        # 终端速览：高风险项
        for r in results:
            highs = [p["label"] or p["name"] for p in r["permissions"] if p["level"] == "high"]
            if highs:
                print(f"\n{r['file']} 高风险权限 {len(highs)} 项：{', '.join(highs[:6])}{' …' if len(highs) > 6 else ''}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
