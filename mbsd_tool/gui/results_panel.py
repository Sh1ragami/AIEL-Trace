from __future__ import annotations

from PySide6.QtCore import Qt, Signal
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
    QScrollArea,
    QFrame,
    QHeaderView,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QTextEdit,
    QAbstractItemView,
    QMessageBox,
)
from PySide6.QtGui import QColor, QBrush

from mbsd_tool.core.models import ScanResult, VulnerabilityFinding


class ResultsPanel(QWidget):
    finding_selected = Signal(str, VulnerabilityFinding)

    def __init__(self) -> None:
        super().__init__()
        # Theme mode for simple styling of severity cards
        self._theme_mode = "light"

        # Severity summary cards (replace charts)
        self._sev_colors_light = {
            "高": "#d32f2f",
            "中": "#f57c00",
            "低": "#388e3c",
            "情報": "#1976d2",
        }
        self._sev_colors_dark = {
            "高": "#7f1d1d",   # deep red
            "中": "#9a3412",   # deep orange
            "低": "#14532d",   # deep green
            "情報": "#1e3a8a", # deep blue
        }
        self.severity_bar = QWidget()
        self.severity_bar.setObjectName("severityBar")
        self._severity_layout = QHBoxLayout(self.severity_bar)
        self._severity_layout.setContentsMargins(0, 0, 0, 0)
        self._severity_layout.setSpacing(10)
        self._sev_cards: dict[str, tuple[QFrame, QLabel]] = {}
        for name in ["高", "中", "低", "情報"]:
            card = QFrame()
            card.setFrameShape(QFrame.NoFrame)
            card.setStyleSheet(
                f"background: {self._sev_colors_light[name]}; border-radius: 10px;"
            )
            vbox = QVBoxLayout(card)
            vbox.setContentsMargins(12, 10, 12, 10)
            title = QLabel(name)
            title.setStyleSheet("color: white; font-weight: bold; letter-spacing: 1px; border: none; background: transparent;")
            title.setFrameShape(QFrame.NoFrame)
            title.setFocusPolicy(Qt.NoFocus)
            count = QLabel("0")
            count.setStyleSheet("color: white; font-size: 28px; font-weight: 600; border: none; background: transparent;")
            count.setFrameShape(QFrame.NoFrame)
            count.setFocusPolicy(Qt.NoFocus)
            vbox.addWidget(title)
            vbox.addWidget(count)
            self._severity_layout.addWidget(card)
            self._sev_cards[name] = (card, count)
        self.summary = QTableWidget(0, 3)
        self.summary.setHorizontalHeaderLabels(["脆弱性", "重要度", "件数"])
        self.summary.setSelectionBehavior(self.summary.SelectionBehavior.SelectRows)
        self.summary.setSelectionMode(self.summary.SelectionMode.SingleSelection)
        self.summary.verticalHeader().setVisible(False)
        self.summary.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.summary.itemSelectionChanged.connect(self._on_summary_selected)
        self.summary.setAlternatingRowColors(True)
        self.summary.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Details table (adds 状態 when baseline loaded)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["エンドポイント", "脆弱性", "重要度", "カテゴリ", "検査タイプ"])
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemDoubleClicked.connect(self._on_detail_clicked)
        self.status_label = QLabel("結果はまだありません")
        # Export (top, compact)
        self.format_combo = QComboBox()
        self.format_combo.addItems(["Markdown", "HTML", "PDF", "PDF (AIEL)", "DOCX (AIEL)"])
        export_btn = QPushButton("エクスポート")
        export_btn.clicked.connect(self.on_export)
        export_bar = QHBoxLayout()
        export_bar.addWidget(QLabel("出力形式"))
        export_bar.addWidget(self.format_combo)
        export_bar.addStretch(1)
        export_bar.addWidget(export_btn)

        # Baseline compare controls
        self._baseline: dict | None = None
        self._diff: dict | None = None
        base_bar = QHBoxLayout()
        self.btn_save_baseline = QPushButton("比較用ファイル保存(JSON)")
        self.btn_load_baseline = QPushButton("前回ファイル読込")
        self.btn_list_fixed = QPushButton("修正済み一覧…")
        self.btn_list_fixed.setEnabled(False)
        self._diff_label = QLabel("")
        self.btn_save_baseline.clicked.connect(self._on_save_baseline)
        self.btn_load_baseline.clicked.connect(self._on_load_baseline)
        self.btn_list_fixed.clicked.connect(self._on_show_fixed)
        base_bar.addWidget(self.btn_save_baseline)
        base_bar.addWidget(self.btn_load_baseline)
        base_bar.addWidget(self.btn_list_fixed)
        base_bar.addStretch(1)
        base_bar.addWidget(self._diff_label)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.addWidget(self._mk_header("結果"))
        layout.addLayout(export_bar)
        layout.addLayout(base_bar)
        # Charts are removed; show severity bar instead
        layout.addWidget(self.severity_bar)
        layout.addWidget(self._mk_header("サマリー"))
        layout.addWidget(self.summary)
        layout.addWidget(self._mk_header("詳細"))
        layout.addWidget(self.table)
        layout.addWidget(self.status_label)

        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(content)
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.addWidget(scroll)

        self._latest: ScanResult | None = None
        self._has_status_column = False

    def _mk_header(self, text: str, _sp: object | None = None) -> QWidget:
        w = QWidget()
        hb = QHBoxLayout(w)
        hb.setContentsMargins(0, 6, 0, 2)
        hb.setSpacing(6)
        title = QLabel(text)
        title.setStyleSheet("font-weight:600;")
        hb.addWidget(title)
        hb.addStretch(1)
        return w

    def update_results(self, result: ScanResult) -> None:
        self._latest = result
        # If baseline loaded, compute diff
        if self._baseline is not None:
            self._compute_diff()
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
        self._update_severity_cards(result)

        # Selecting a row in summary filters details (connected in __init__)

    def on_export(self) -> None:
        if not self._latest:
            return
        fmt = self.format_combo.currentText()
        filters = {
            "Markdown": "Markdown (*.md)",
            "HTML": "HTML (*.html)",
            "PDF": "PDF (*.pdf)",
            "PDF (AIEL)": "PDF (*.pdf)",
            "DOCX (AIEL)": "Word (*.docx)",
        }
        default_name = {
            "Markdown": "report.md",
            "HTML": "report.html",
            "PDF": "report.pdf",
            "PDF (AIEL)": "report_aiel.pdf",
            "DOCX (AIEL)": "report_aiel.docx",
        }[fmt]
        path, _ = QFileDialog.getSaveFileName(self, f"{fmt}を保存", default_name, filters[fmt])
        if not path:
            return
        try:
            from mbsd_tool.core.report import export_report
            key_map = {
                "Markdown": "company_markdown",
                "HTML": "company_html",
                "PDF": "company_pdf",
                "PDF (AIEL)": "aiel_pdf",
                "DOCX (AIEL)": "aiel_docx",
            }
            export_report(self._latest, path, key_map.get(fmt, fmt.lower()), None)
            self.status_label.setText(f"保存しました: {path}")
        except Exception as e:
            msg_box = QMessageBox(self)
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("エクスポートエラー")
            msg_box.setText("レポートのエクスポート中にエラーが発生しました。")
            msg_box.setInformativeText(str(e))
            msg_box.exec()

    def _populate_details(self, filter_key: tuple | None = None) -> None:
        if not self._latest:
            return
        # Ensure status column exists if baseline loaded
        want_status = self._baseline is not None
        if want_status and not self._has_status_column:
            self.table.setColumnCount(6)
            self.table.setHorizontalHeaderLabels(["エンドポイント", "脆弱性", "重要度", "カテゴリ", "検査タイプ", "状態"])
            self._has_status_column = True
        if not want_status and self._has_status_column:
            self.table.setColumnCount(5)
            self.table.setHorizontalHeaderLabels(["エンドポイント", "脆弱性", "重要度", "カテゴリ", "検査タイプ"])
            self._has_status_column = False

        rows = 0
        self._detail_rows: list[tuple[str, object]] = []
        for endpoint, vulns in self._latest.vulns_by_endpoint.items():
            for v in vulns:
                if filter_key and (v.name, v.severity) != filter_key:
                    continue
                rows += 1
        self.table.setRowCount(rows)
        r = 0
        diff_status = {}
        if self._diff is not None:
            for it in self._diff.get("new", []):
                diff_status[it["key"]] = "新規"
            for it in self._diff.get("unresolved", []):
                diff_status[it["key"]] = "未解決"
        for endpoint, vulns in self._latest.vulns_by_endpoint.items():
            for v in vulns:
                if filter_key and (v.name, v.severity) != filter_key:
                    continue
                self.table.setItem(r, 0, QTableWidgetItem(endpoint))
                self.table.setItem(r, 1, QTableWidgetItem(v.name))
                self.table.setItem(r, 2, self._sev_item(v.severity))
                self.table.setItem(r, 3, QTableWidgetItem(v.category or ""))
                self.table.setItem(r, 4, QTableWidgetItem(v.test_type or ""))
                if self._baseline is not None:
                    # status column
                    try:
                        from mbsd_tool.core.baseline import _finding_key  # type: ignore
                        k = _finding_key(endpoint, v)
                        st = diff_status.get(k, "")
                        self.table.setItem(r, 5, QTableWidgetItem(st))
                    except Exception:
                        self.table.setItem(r, 5, QTableWidgetItem(""))
                # keep reference to the underlying finding for detail view
                self._detail_rows.append((endpoint, v))
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

    def _on_detail_clicked(self, item) -> None:
        if not hasattr(self, "_detail_rows"):
            return
        row = item.row()
        if row < 0 or row >= len(self._detail_rows):
            return
        endpoint, finding = self._detail_rows[row]
        # 新しいシグナルを発信
        self.finding_selected.emit(endpoint, finding)
        # 既存の詳細ダイアログ表示
        self._show_vuln_detail(endpoint, finding)

    def _show_vuln_detail(self, endpoint: str, v) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("脆弱性の詳細")
        layout = QVBoxLayout(dlg)
        title = QLabel(v.name)
        title.setStyleSheet("font-size:16px;font-weight:600;")
        layout.addWidget(title)
        form = QFormLayout()
        form.addRow("エンドポイント", QLabel(endpoint))
        form.addRow("重要度", QLabel(v.severity))
        if v.category:
            form.addRow("カテゴリ", QLabel(v.category))
        if v.test_type:
            form.addRow("検査タイプ", QLabel(v.test_type))
        layout.addLayout(form)
        def add_block(label: str, text: str | None):
            if not text:
                return
            layout.addWidget(QLabel(label))
            te = QTextEdit(); te.setReadOnly(True); te.setText(text)
            te.setMinimumHeight(80)
            layout.addWidget(te)
        add_block("解説", v.explanation)
        add_block("証拠", v.evidence)
        if v.reproduction_steps:
            add_block("再現手順", "\n".join(f"- {s}" for s in v.reproduction_steps))
        add_block("想定される被害・影響", v.impact)
        add_block("対策", v.remediation)
        add_block("備考", v.notes)
        btns = QDialogButtonBox(QDialogButtonBox.Ok)
        btns.accepted.connect(dlg.accept)
        layout.addWidget(btns)
        dlg.resize(600, 500)
        dlg.exec()

    def _update_severity_cards(self, result: ScanResult) -> None:
        sev_counts = {"高": 0, "中": 0, "低": 0, "情報": 0}
        for _, vulns in result.vulns_by_endpoint.items():
            for v in vulns:
                sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1
        for name, (_, label) in self._sev_cards.items():
            label.setText(str(sev_counts.get(name, 0)))
        # Apply theme in case it changed
        self.set_theme(self._theme_mode)

    def set_theme(self, mode: str) -> None:
        self._theme_mode = mode
        # Adjust card styles if necessary for light/dark（枠線なし）
        for name, (card, _) in self._sev_cards.items():
            if mode == "dark":
                color = self._sev_colors_dark[name]
            else:
                color = self._sev_colors_light[name]
            card.setStyleSheet(f"background: {color}; border-radius: 10px;")

    def _sev_item(self, sev: str) -> QTableWidgetItem:
        item = QTableWidgetItem(sev)
        # Japanese severity words expected: 高 / 中 / 低 / 情報
        if self._theme_mode == "dark":
            colors = {
                '高': QColor('#7f1d1d'),
                '中': QColor('#9a3412'),
                '低': QColor('#14532d'),
                '情報': QColor('#1e3a8a'),
            }
        else:
            colors = {
                '高': QColor('#d32f2f'),
                '中': QColor('#f57c00'),
                '低': QColor('#388e3c'),
                '情報': QColor('#1976d2'),
            }
        c = colors.get(sev, QColor('#607d8b'))
        item.setForeground(QBrush(QColor('#ffffff')))
        item.setBackground(QBrush(c))
        return item

    # --- Baseline handlers ---
    def _on_save_baseline(self) -> None:
        if not self._latest:
            return
        path, _ = QFileDialog.getSaveFileName(self, "比較用ファイルを保存", "baseline.json", "JSON (*.json)")
        if not path:
            return
        try:
            from mbsd_tool.core.baseline import save_baseline
            save_baseline(self._latest, path)
            self.status_label.setText(f"比較用ファイルを保存しました: {path}")
        except Exception as e:
            msg_box = QMessageBox(self)
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("保存エラー")
            msg_box.setText("比較用ファイルの保存に失敗しました。")
            msg_box.setInformativeText(str(e))
            msg_box.exec()

    def _on_load_baseline(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "前回の比較用ファイルを読み込む", "", "JSON (*.json)")
        if not path:
            return
        try:
            from mbsd_tool.core.baseline import load_baseline
            self._baseline = load_baseline(path)
            if self._latest is not None:
                self._compute_diff()
                self._populate_details()
                self.status_label.setText("前回ファイルを読み込み、差分を表示しました。")
            else:
                self.status_label.setText("前回ファイルを読み込みました。次回のスキャン結果で差分表示します。")
        except Exception as e:
            msg_box = QMessageBox(self)
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("読み込みエラー")
            msg_box.setText("比較用ファイルの読み込みに失敗しました。")
            msg_box.setInformativeText(str(e))
            msg_box.exec()

    def _compute_diff(self) -> None:
        if self._baseline is None or self._latest is None:
            self._diff = None
            self._diff_label.setText("")
            self.btn_list_fixed.setEnabled(False)
            return
        from mbsd_tool.core.baseline import diff_against_baseline
        self._diff = diff_against_baseline(self._baseline, self._latest)
        sm = self._diff.get("summary", {}) if isinstance(self._diff, dict) else {}
        self._diff_label.setText(f"新規: {sm.get('new',0)}  未解決: {sm.get('unresolved',0)}  修正済: {sm.get('fixed',0)}")
        self.btn_list_fixed.setEnabled((sm.get('fixed', 0) or 0) > 0)

    def _on_show_fixed(self) -> None:
        if not self._diff:
            return
        fixed = self._diff.get("fixed", [])
        dlg = QDialog(self)
        dlg.setWindowTitle("修正済みの脆弱性")
        v = QVBoxLayout(dlg)
        table = QTableWidget(len(fixed), 2)
        table.setHorizontalHeaderLabels(["エンドポイント", "脆弱性"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        for i, it in enumerate(fixed):
            table.setItem(i, 0, QTableWidgetItem(it.get("endpoint") or ""))
            table.setItem(i, 1, QTableWidgetItem(it.get("name") or ""))
        v.addWidget(table)
        btns = QDialogButtonBox(QDialogButtonBox.Ok)
        btns.accepted.connect(dlg.accept)
        v.addWidget(btns)
        dlg.resize(600, 400)
        dlg.exec()
