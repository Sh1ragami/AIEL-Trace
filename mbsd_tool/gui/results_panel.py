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
    QComboBox,
)
from PySide6.QtWidgets import QHeaderView
from PySide6.QtGui import QColor, QBrush

from mbsd_tool.core.models import ScanResult
from mbsd_tool.core.report import export_report


class ResultsPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.summary = QTableWidget(0, 3)
        self.summary.setHorizontalHeaderLabels(["脆弱性", "重要度", "件数"])
        self.summary.setSelectionBehavior(self.summary.SelectionBehavior.SelectRows)
        self.summary.setSelectionMode(self.summary.SelectionMode.SingleSelection)
        self.summary.verticalHeader().setVisible(False)
        self.summary.itemSelectionChanged.connect(self._on_summary_selected)
        self.summary.setAlternatingRowColors(True)
        self.summary.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["エンドポイント", "脆弱性", "重要度", "カテゴリ", "検査タイプ"])
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.status_label = QLabel("結果はまだありません")
        # Export (top, compact)
        self.format_combo = QComboBox()
        self.format_combo.addItems(["指定形式(Markdown)", "指定形式(HTML)", "指定形式(PDF)"])
        export_btn = QPushButton("エクスポート")
        export_btn.clicked.connect(self.on_export)
        export_bar = QHBoxLayout()
        export_bar.addWidget(QLabel("出力形式"))
        export_bar.addWidget(self.format_combo)
        export_bar.addStretch(1)
        export_bar.addWidget(export_btn)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("結果"))
        layout.addLayout(export_bar)
        layout.addWidget(QLabel("サマリー"))
        layout.addWidget(self.summary)
        layout.addWidget(QLabel("詳細"))
        layout.addWidget(self.table)
        layout.addWidget(self.status_label)

        self._latest: ScanResult | None = None

    def update_results(self, result: ScanResult) -> None:
        self._latest = result
        # サマリー
        counts = {}
        for endpoint, vulns in result.vulns_by_endpoint.items():
            for v in vulns:
                key = (v.name, v.severity)
                counts[key] = counts.get(key, 0) + 1
        self.summary.setRowCount(len(counts))
        for i, ((name, sev), cnt) in enumerate(counts.items()):
            self.summary.setItem(i, 0, QTableWidgetItem(name))
            self.summary.setItem(i, 1, self._sev_item(sev))
            self.summary.setItem(i, 2, QTableWidgetItem(str(cnt)))

        self._populate_details()
        total = sum(counts.values())
        self.status_label.setText(f"スキャン対象: {len(result.endpoints)}  検出: {total}")

        # Selecting a row in summary filters details (connected in __init__)

    def on_export(self) -> None:
        if not self._latest:
            return
        fmt = self.format_combo.currentText()
        filters = {
            "指定形式(Markdown)": "Markdown (*.md)",
            "指定形式(HTML)": "HTML (*.html)",
            "指定形式(PDF)": "PDF (*.pdf)",
        }
        default_name = {
            "指定形式(Markdown)": "report_company.md",
            "指定形式(HTML)": "report_company.html",
            "指定形式(PDF)": "report_company.pdf",
        }[fmt]
        path, _ = QFileDialog.getSaveFileName(self, f"{fmt}を保存", default_name, filters[fmt])
        if not path:
            return
        try:
            export_report(self._latest, path, fmt.lower(), None)
            self.status_label.setText(f"保存しました: {path}")
        except Exception as e:
            self.status_label.setText(f"エクスポートエラー: {e}")

    def _populate_details(self, filter_key: tuple | None = None) -> None:
        if not self._latest:
            return
        rows = 0
        for endpoint, vulns in self._latest.vulns_by_endpoint.items():
            for v in vulns:
                if filter_key and (v.name, v.severity) != filter_key:
                    continue
                rows += 1
        self.table.setRowCount(rows)
        r = 0
        for endpoint, vulns in self._latest.vulns_by_endpoint.items():
            for v in vulns:
                if filter_key and (v.name, v.severity) != filter_key:
                    continue
                self.table.setItem(r, 0, QTableWidgetItem(endpoint))
                self.table.setItem(r, 1, QTableWidgetItem(v.name))
                self.table.setItem(r, 2, self._sev_item(v.severity))
                self.table.setItem(r, 3, QTableWidgetItem(v.category or ""))
                self.table.setItem(r, 4, QTableWidgetItem(v.test_type or ""))
                r += 1

    def _on_summary_selected(self) -> None:
        rows = self.summary.selectionModel().selectedRows()
        if not rows:
            self._populate_details(None)
            return
        row = rows[0].row()
        name = self.summary.item(row, 0).text()
        sev = self.summary.item(row, 1).text()
        self._populate_details((name, sev))

    def _sev_item(self, sev: str) -> QTableWidgetItem:
        item = QTableWidgetItem(sev)
        # Japanese severity words expected: 高 / 中 / 低
        colors = {
            '高': QColor('#d32f2f'),
            '中': QColor('#f57c00'),
            '低': QColor('#388e3c'),
        }
        c = colors.get(sev, QColor('#455a64'))
        item.setForeground(QBrush(QColor('#ffffff')))
        item.setBackground(QBrush(c))
        return item
