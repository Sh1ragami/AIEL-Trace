from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHBoxLayout,
    QFileDialog,
)

from mbsd_tool.core.models import ScanResult
from mbsd_tool.core.report import export_markdown, export_json


class ResultsPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["エンドポイント", "脆弱性", "重要度", "証拠", "再現手順"])
        self.status_label = QLabel("結果はまだありません")

        self.export_md_btn = QPushButton("Markdown出力…")
        self.export_md_btn.clicked.connect(self.on_export_md)
        self.export_json_btn = QPushButton("JSON出力…")
        self.export_json_btn.clicked.connect(self.on_export_json)

        btns = QHBoxLayout()
        btns.addWidget(self.export_md_btn)
        btns.addWidget(self.export_json_btn)
        btns.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("結果"))
        layout.addWidget(self.table)
        layout.addLayout(btns)
        layout.addWidget(self.status_label)

        self._latest: ScanResult | None = None

    def update_results(self, result: ScanResult) -> None:
        self._latest = result
        rows = sum(len(vs) for vs in result.vulns_by_endpoint.values())
        self.table.setRowCount(rows)
        r = 0
        for endpoint, vulns in result.vulns_by_endpoint.items():
            for v in vulns:
                self.table.setItem(r, 0, QTableWidgetItem(endpoint))
                self.table.setItem(r, 1, QTableWidgetItem(v.name))
                self.table.setItem(r, 2, QTableWidgetItem(v.severity))
                self.table.setItem(r, 3, QTableWidgetItem(v.evidence or ""))
                self.table.setItem(r, 4, QTableWidgetItem(" -> ".join(v.reproduction_steps or [])))
                r += 1
        self.status_label.setText(f"スキャン対象: {len(result.endpoints)}  検出: {rows}")

    def on_export_md(self) -> None:
        if not self._latest:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Markdownを保存", "report.md", "Markdown (*.md)")
        if path:
            export_markdown(self._latest, path)
            self.status_label.setText(f"保存しました: {path}")

    def on_export_json(self) -> None:
        if not self._latest:
            return
        path, _ = QFileDialog.getSaveFileName(self, "JSONを保存", "report.json", "JSON (*.json)")
        if path:
            export_json(self._latest, path)
            self.status_label.setText(f"保存しました: {path}")
