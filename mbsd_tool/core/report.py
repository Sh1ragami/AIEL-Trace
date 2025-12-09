from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO

from mbsd_tool.core.models import ScanResult


def export_markdown(result: ScanResult, path: str | Path) -> None:
    p = Path(path)
    with p.open("w", encoding="utf-8") as f:
        _write_markdown(result, f)


def _write_markdown(result: ScanResult, f: TextIO) -> None:
    f.write(f"# 脆弱性診断レポート\n\n")
    f.write(f"対象: {result.target}\n\n")
    f.write(f"モード: {result.mode.value}\n\n")
    for endpoint, vulns in result.vulns_by_endpoint.items():
        f.write(f"## {endpoint}\n\n")
        if not vulns:
            f.write("- 問題は検出されませんでした\n\n")
            continue
        for v in vulns:
            f.write(f"- 脆弱性: {v.name}\n")
            f.write(f"  - 重要度: {v.severity}\n")
            if v.evidence:
                f.write(f"  - 証拠: {v.evidence}\n")
            if v.reproduction_steps:
                f.write(f"  - 再現手順:\n")
                for s in v.reproduction_steps:
                    f.write(f"    1. {s}\n")
            f.write("\n")


def export_json(result: ScanResult, path: str | Path) -> None:
    p = Path(path)
    with p.open("w", encoding="utf-8") as f:
        json.dump(result.model_dump(), f, indent=2, ensure_ascii=False)
