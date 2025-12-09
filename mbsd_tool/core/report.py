from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO

from mbsd_tool.core.models import ScanResult, VulnerabilityFinding
from jinja2 import Template


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


def _filter_fields(v: VulnerabilityFinding, fields: dict) -> dict:
    d = {}
    if fields.get("name"):
        d["name"] = v.name
    if fields.get("severity"):
        d["severity"] = v.severity
    if fields.get("evidence") and v.evidence:
        d["evidence"] = v.evidence
    if fields.get("repro") and v.reproduction_steps:
        d["reproduction_steps"] = v.reproduction_steps
    if fields.get("notes") and v.notes:
        d["notes"] = v.notes
    return d


def export_html(result: ScanResult, path: str | Path, fields: dict | None = None) -> None:
    fields = fields or {"endpoint": True, "name": True, "severity": True, "evidence": True, "repro": True, "notes": True}
    tpl = Template(
        """
        <!doctype html>
        <html lang="ja">
        <head>
          <meta charset="utf-8">
          <title>脆弱性診断レポート</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; padding: 16px; }
            h1 { margin: 0 0 12px; }
            h2 { margin: 18px 0 6px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
            th { background: #f5f5f5; text-align: left; }
            code { background: #f6f8fa; padding: 2px 4px; }
          </style>
        </head>
        <body>
          <h1>脆弱性診断レポート</h1>
          <div>対象: {{ target }}</div>
          <div>モード: {{ mode }}</div>
          {% for endpoint, vulns in items %}
            <h2>{{ endpoint }}</h2>
            {% if not vulns %}
              <p>問題は検出されませんでした</p>
            {% else %}
              <table>
                <thead>
                  <tr>
                    {% if fields.name %}<th>脆弱性</th>{% endif %}
                    {% if fields.severity %}<th>重要度</th>{% endif %}
                    {% if fields.evidence %}<th>証拠</th>{% endif %}
                    {% if fields.repro %}<th>再現手順</th>{% endif %}
                    {% if fields.notes %}<th>備考</th>{% endif %}
                  </tr>
                </thead>
                <tbody>
                {% for v in vulns %}
                  <tr>
                    {% if fields.name %}<td>{{ v.name }}</td>{% endif %}
                    {% if fields.severity %}<td>{{ v.severity }}</td>{% endif %}
                    {% if fields.evidence %}<td>{{ v.evidence or '' }}</td>{% endif %}
                    {% if fields.repro %}<td>{% if v.reproduction_steps %}<ol>{% for s in v.reproduction_steps %}<li>{{ s }}</li>{% endfor %}</ol>{% endif %}</td>{% endif %}
                    {% if fields.notes %}<td>{{ v.notes or '' }}</td>{% endif %}
                  </tr>
                {% endfor %}
                </tbody>
              </table>
            {% endif %}
          {% endfor %}
        </body>
        </html>
        """
    )
    html = tpl.render(
        target=result.target,
        mode=result.mode.value,
        items=result.vulns_by_endpoint.items(),
        fields=fields,
    )
    Path(path).write_text(html, encoding="utf-8")


def export_pdf(result: ScanResult, path: str | Path, fields: dict | None = None) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import mm
    except Exception as e:
        raise RuntimeError("reportlabがインストールされていません") from e
    fields = fields or {"endpoint": True, "name": True, "severity": True, "evidence": True, "repro": True, "notes": True}
    c = canvas.Canvas(str(path), pagesize=A4)
    width, height = A4
    margin = 15 * mm
    x = margin
    y = height - margin
    def write_line(text: str, leading: float = 12.0, indent: float = 0.0):
        nonlocal y
        if y < margin:
            c.showPage()
            y = height - margin
        c.drawString(x + indent, y, text)
        y -= leading

    c.setFont("Helvetica-Bold", 14)
    write_line("脆弱性診断レポート", 18)
    c.setFont("Helvetica", 10)
    write_line(f"対象: {result.target}")
    write_line(f"モード: {result.mode.value}")
    for endpoint, vulns in result.vulns_by_endpoint.items():
        c.setFont("Helvetica-Bold", 12)
        write_line(endpoint, 16)
        if not vulns:
            c.setFont("Helvetica", 10)
            write_line("問題は検出されませんでした", 12, 10)
            continue
        for v in vulns:
            c.setFont("Helvetica-Bold", 11)
            if fields.get("name"):
                write_line(f"脆弱性: {v.name}", 14, 10)
            c.setFont("Helvetica", 10)
            if fields.get("severity"):
                write_line(f"重要度: {v.severity}", 12, 12)
            if fields.get("evidence") and v.evidence:
                write_line(f"証拠: {v.evidence}", 12, 12)
            if fields.get("repro") and v.reproduction_steps:
                write_line("再現手順:", 12, 12)
                for s in v.reproduction_steps:
                    write_line(f"- {s}", 12, 20)
            if fields.get("notes") and v.notes:
                write_line(f"備考: {v.notes}", 12, 12)
    c.save()


def export_report(result: ScanResult, path: str | Path, fmt: str, fields: dict | None = None) -> None:
    fmt = fmt.lower()
    if fmt == "markdown":
        export_markdown(result, path)
    elif fmt == "json":
        export_json(result, path)
    elif fmt == "html":
        export_html(result, path, fields)
    elif fmt == "pdf":
        export_pdf(result, path, fields)
    elif fmt in ("指定形式(markdown)", "company_markdown", "custom_markdown"):
        export_company_markdown(result, path)
    elif fmt in ("指定形式(html)", "company_html", "custom_html"):
        export_company_html(result, path)
    elif fmt in ("指定形式(pdf)", "company_pdf", "custom_pdf"):
        export_company_pdf(result, path)
    else:
        raise ValueError(f"未知の形式: {fmt}")


def export_company_markdown(result: ScanResult, path: str | Path) -> None:
    p = Path(path)
    with p.open("w", encoding="utf-8") as f:
        idx = 1
        for endpoint, vulns in result.vulns_by_endpoint.items():
            for v in vulns:
                f.write(f"[{idx}] {v.name}\n")
                f.write("* 対象\n")
                f.write(f"{v.feature_name or '不明'}\n")
                f.write(f"{endpoint}\n\n")
                f.write("* 危険度\n")
                f.write(f"{v.severity}\n\n")
                f.write("* 解説\n")
                f.write(f"{v.explanation or v.evidence or ''}\n\n")
                f.write("* 想定される被害・影響\n")
                f.write(f"{v.impact or ''}\n\n")
                f.write("* 対策\n")
                f.write(f"{v.remediation or ''}\n\n")
                f.write("* 備考\n")
                f.write(f"{v.notes or ''}\n\n")
                idx += 1


def export_company_html(result: ScanResult, path: str | Path) -> None:
    tpl = Template(
        """
        <!doctype html><html lang="ja"><head>
        <meta charset="utf-8"/>
        <title>脆弱性診断レポート（指定形式）</title>
        <style>
        body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI, sans-serif; padding:16px;}
        h2{margin:14px 0 6px}
        .block{margin:18px 0 24px;}
        .label{font-weight:600;}
        .mono{font-family:ui-monospace, SFMono-Regular, Menlo, monospace}
        .box{border:1px solid #ddd; padding:8px; background:#fafafa}
        </style>
        </head><body>
        <h1>脆弱性診断レポート（指定形式）</h1>
        {% set i = 1 %}
        {% for endpoint, vulns in items %}
          {% for v in vulns %}
            <div class="block">
              <h2>[{{ i }}] {{ v.name }}</h2>
              <div class="label">* 対象</div>
              <div class="box">{{ v.feature_name or '不明' }}<br/><span class="mono">{{ endpoint }}</span></div>
              <div class="label">* 危険度</div>
              <div class="box">{{ v.severity }}</div>
              <div class="label">* 解説</div>
              <div class="box">{{ v.explanation or v.evidence or '' }}</div>
              <div class="label">* 想定される被害・影響</div>
              <div class="box">{{ v.impact or '' }}</div>
              <div class="label">* 対策</div>
              <div class="box">{{ v.remediation or '' }}</div>
              <div class="label">* 備考</div>
              <div class="box">{{ v.notes or '' }}</div>
            </div>
            {% set i = i + 1 %}
          {% endfor %}
        {% endfor %}
        </body></html>
        """
    )
    html = tpl.render(items=result.vulns_by_endpoint.items())
    Path(path).write_text(html, encoding="utf-8")


def export_company_pdf(result: ScanResult, path: str | Path) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import mm
    except Exception as e:
        raise RuntimeError("reportlabがインストールされていません") from e
    c = canvas.Canvas(str(path), pagesize=A4)
    width, height = A4
    margin = 15 * mm
    x = margin
    y = height - margin
    def write_line(text: str, leading: float = 12.0, indent: float = 0.0, bold: bool = False):
        nonlocal y
        if y < margin:
            c.showPage(); y = height - margin
        if bold:
            c.setFont("Helvetica-Bold", 11)
        else:
            c.setFont("Helvetica", 10)
        c.drawString(x + indent, y, text)
        y -= leading

    idx = 1
    c.setFont("Helvetica-Bold", 14); write_line("脆弱性診断レポート（指定形式）", 18)
    for endpoint, vulns in result.vulns_by_endpoint.items():
        for v in vulns:
            write_line(f"[{idx}] {v.name}", 16, 0, True)
            write_line("* 対象", 12, 0, True)
            write_line(f"{v.feature_name or '不明'}", 12, 10)
            write_line(endpoint, 12, 10)
            write_line("* 危険度", 12, 0, True)
            write_line(v.severity, 12, 10)
            write_line("* 解説", 12, 0, True)
            write_line(v.explanation or v.evidence or "", 12, 10)
            write_line("* 想定される被害・影響", 12, 0, True)
            write_line(v.impact or "", 12, 10)
            write_line("* 対策", 12, 0, True)
            write_line(v.remediation or "", 12, 10)
            write_line("* 備考", 12, 0, True)
            write_line(v.notes or "", 16, 10)
            idx += 1
    c.save()
