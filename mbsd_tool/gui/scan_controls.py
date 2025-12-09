from __future__ import annotations

from typing import List

from PySide6.QtCore import Qt, Signal, QThreadPool
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QLabel,
    QGroupBox,
    QCheckBox,
    QToolButton,
)

from mbsd_tool.core.enumerator import enumerate_paths_worker
from mbsd_tool.core.scanner import scan_targets_worker
from mbsd_tool.core.models import ScanMode, ScanResult, AuthConfig, ScanOptions, XSSOptions, SQLIOptions
from mbsd_tool.core.auth import login_worker


class ScanControls(QWidget):
    load_in_browser_requested = Signal(str)
    scan_completed = Signal(ScanResult)
    auth_config_changed = Signal(AuthConfig, bool)
    deep_scan_requested = Signal(list)

    def __init__(self) -> None:
        super().__init__()

        self.thread_pool = QThreadPool.globalInstance()
        self._enum_worker = None
        self._scan_worker = None
        self._login_worker = None

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("http://localhost:80/")

        self.mode_combo = QComboBox()
        self.mode_combo.addItems([m.value for m in ScanMode])

        self.enumerate_btn = QPushButton("パス列挙")
        self.enumerate_btn.clicked.connect(self.on_enumerate)

        self.scan_btn = QPushButton("エンドポイントをスキャン")
        self.scan_btn.clicked.connect(self.on_scan)
        self.scan_btn.setEnabled(False)

        # 自動表示にするため、ボタンは配置しない（必要なら再表示可）
        self.open_in_browser_btn = QPushButton("エージェントブラウザで開く")
        self.open_in_browser_btn.clicked.connect(self.on_open_in_browser)
        self.open_in_browser_btn.setVisible(False)

        self.status_label = QLabel("待機中")
        self.deep_scan_checkbox = QCheckBox("自動深度スキャン（ブラウザでAI操作/DOM検査）")
        self.deep_scan_checkbox.setChecked(False)

        self.paths_table = QTableWidget(0, 1)
        self.paths_table.setHorizontalHeaderLabels(["パス/URL"])
        self.paths_table.setSelectionBehavior(self.paths_table.SelectionBehavior.SelectRows)
        self.paths_table.setSelectionMode(self.paths_table.SelectionMode.SingleSelection)
        self.paths_table.setAlternatingRowColors(True)
        self.paths_table.horizontalHeader().setStretchLastSection(True)
        self.paths_table.verticalHeader().setVisible(False)

        top_form = QFormLayout()
        top_form.addRow("ターゲット", self.target_input)
        top_form.addRow("モード", self.mode_combo)
        top_form.addRow("", self.deep_scan_checkbox)

        # 認証設定
        self.login_url_input = QLineEdit()
        self.login_url_input.setPlaceholderText("http://localhost:80/login")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("ユーザー名/メール")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("パスワード")
        self.login_btn = QPushButton("ログイン試行")
        self.login_btn.clicked.connect(self.on_login_try)
        self.share_ai_checkbox = QCheckBox("AIに認証情報を共有（ローカルLLM）")
        self.share_ai_checkbox.setChecked(False)
        self.share_ai_checkbox.toggled.connect(lambda _: self._emit_auth_changed())

        self.auth_box = QGroupBox("認証")
        auth_form = QFormLayout()
        auth_form.addRow("ログインURL", self.login_url_input)
        auth_form.addRow("ユーザー名/メール", self.username_input)
        auth_form.addRow("パスワード", self.password_input)
        auth_form.addRow("", self.login_btn)
        auth_form.addRow("", self.share_ai_checkbox)
        self.auth_box.setLayout(auth_form)

        # 比較用アカウント（上位権限など）
        self.alt_login_url_input = QLineEdit()
        self.alt_username_input = QLineEdit()
        self.alt_password_input = QLineEdit(); self.alt_password_input.setEchoMode(QLineEdit.Password)
        self.alt_box = QGroupBox("比較用アカウント（上位権限）")
        alt_form = QFormLayout()
        alt_form.addRow("ログインURL", self.alt_login_url_input)
        alt_form.addRow("ユーザー名/メール", self.alt_username_input)
        alt_form.addRow("パスワード", self.alt_password_input)
        self.alt_box.setLayout(alt_form)

        # オプション設定（XSS/SQLi）
        self.xss_enable = QCheckBox("XSS検査を有効化")
        self.xss_enable.setChecked(True)
        self.xss_param = QLineEdit(); self.xss_param.setText("q")
        self.xss_payload = QLineEdit(); self.xss_payload.setText("<xss>XSS</xss>")
        self.xss_tokens = QLineEdit(); self.xss_tokens.setText("XSS,xss")

        xss_form = QFormLayout()
        xss_form.addRow(self.xss_enable)
        xss_form.addRow("パラメータ名", self.xss_param)
        xss_form.addRow("ペイロード", self.xss_payload)
        xss_form.addRow("成功トークン(カンマ区切り)", self.xss_tokens)

        self.sqli_enable = QCheckBox("SQLi検査を有効化（攻撃モードのみ）")
        self.sqli_enable.setChecked(False)
        self.sqli_param = QLineEdit(); self.sqli_param.setText("id")
        self.sqli_baseline = QLineEdit(); self.sqli_baseline.setText("1")
        self.sqli_template = QLineEdit(); self.sqli_template.setText("1 OR 1=1")

        sqli_form = QFormLayout()
        sqli_form.addRow(self.sqli_enable)
        sqli_form.addRow("パラメータ名", self.sqli_param)
        sqli_form.addRow("ベース値", self.sqli_baseline)
        sqli_form.addRow("注入テンプレート", self.sqli_template)

        # Upload tests (attack mode only)
        self.upload_enable = QCheckBox("ファイルアップロード検査を有効化（攻撃モード）")
        self.upload_enable.setChecked(False)
        up_form = QFormLayout()
        up_form.addRow(self.upload_enable)

        opts_box = QGroupBox("スキャンオプション")
        opts_layout = QVBoxLayout()
        opts_layout.addLayout(xss_form)
        opts_layout.addLayout(sqli_form)
        opts_layout.addLayout(up_form)
        opts_box.setLayout(opts_layout)

        # 上部に大きめボタンで配置
        btns = QHBoxLayout()
        for b in (self.enumerate_btn, self.scan_btn):
            b.setMinimumHeight(36)
            b.setStyleSheet("font-size: 14px; padding: 6px 14px;")
        btns.addWidget(self.enumerate_btn)
        btns.addWidget(self.scan_btn)
        btns.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addLayout(top_form)
        # Collapsible toggles
        self.auth_toggle = QToolButton()
        self.auth_toggle.setText("認証を表示")
        self.auth_toggle.setCheckable(True)
        self.auth_toggle.setChecked(False)
        self.auth_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.auth_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.auth_toggle.clicked.connect(self._toggle_auth)

        self.alt_toggle = QToolButton()
        self.alt_toggle.setText("比較用アカウントを表示")
        self.alt_toggle.setCheckable(True)
        self.alt_toggle.setChecked(False)
        self.alt_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.alt_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.alt_toggle.clicked.connect(self._toggle_alt)

        layout.addWidget(self.auth_toggle)
        layout.addWidget(self.auth_box)
        self.auth_box.setVisible(False)
        layout.addWidget(self.alt_toggle)
        layout.addWidget(self.alt_box)
        self.alt_box.setVisible(False)
        layout.addLayout(btns)
        # 折りたたみ可能なオプション
        self.opts_toggle = QToolButton()
        self.opts_toggle.setText("スキャンオプションを表示")
        self.opts_toggle.setCheckable(True)
        self.opts_toggle.setChecked(False)
        self.opts_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.opts_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.opts_toggle.clicked.connect(self._toggle_options)

        layout.addWidget(self.opts_toggle)
        layout.addWidget(opts_box)
        opts_box.setVisible(False)

        layout.addWidget(QLabel("検出されたパス"))
        layout.addWidget(self.paths_table)
        layout.addWidget(self.status_label)

        self.discovered_urls: List[str] = []
        # propagate auth config initially
        self._emit_auth_changed()
        # 行選択で自動的に右側ブラウザで開く
        self.paths_table.itemSelectionChanged.connect(self._on_path_selected)

        # Styling for unified look
        self.setStyleSheet(
            """
            QGroupBox { font-weight: bold; margin-top: 6px; }
            QGroupBox::title { subcontrol-origin: margin; left: 6px; padding: 0 2px; }
            QLabel { font-size: 13px; }
            QLineEdit, QComboBox, QTableWidget { font-size: 13px; }
            QToolButton { font-size: 13px; }
            """
        )

    def on_enumerate(self) -> None:
        base = self.target_input.text().strip()
        if not base:
            self.status_label.setText("ターゲットを入力してください")
            return
        self.paths_table.setRowCount(0)
        self.status_label.setText("列挙中…")

        worker = enumerate_paths_worker(base, self._auth_config())
        self._enum_worker = worker
        worker.signals.result.connect(self._on_enumeration_done)
        worker.signals.error.connect(self._on_enum_error)
        worker.signals.progress.connect(lambda n: self.status_label.setText(f"列挙中… {n}"))
        self.thread_pool.start(worker)

    def _on_enumeration_done(self, urls: List[str]) -> None:
        self._enum_worker = None
        self.discovered_urls = urls
        self.paths_table.setRowCount(len(urls))
        for r, u in enumerate(urls):
            item = QTableWidgetItem(u)
            item.setFlags(item.flags() ^ Qt.ItemIsEditable)
            self.paths_table.setItem(r, 0, item)
        self.scan_btn.setEnabled(len(urls) > 0)
        self.status_label.setText(f"{len(urls)}件のエンドポイントを検出")
        if self.deep_scan_checkbox.isChecked() and urls:
            self.deep_scan_requested.emit(urls)

    def _on_enum_error(self, e: str) -> None:
        self._enum_worker = None
        self.status_label.setText(f"エラー: {e}")

    def on_scan(self) -> None:
        if not self.discovered_urls:
            self.status_label.setText("スキャン対象がありません")
            return
        mode = ScanMode(self.mode_combo.currentText())
        self.status_label.setText("スキャン中…")

        worker = scan_targets_worker(self.discovered_urls, mode, self._auth_config(), self._alt_auth_config(), self._scan_options())
        self._scan_worker = worker
        worker.signals.result.connect(self._on_scan_done)
        worker.signals.error.connect(self._on_scan_error)
        worker.signals.progress.connect(lambda t: self.status_label.setText(t))
        self.thread_pool.start(worker)

    def _on_scan_done(self, result: ScanResult) -> None:
        self._scan_worker = None
        self.status_label.setText("スキャン完了")
        self.scan_completed.emit(result)

    def _on_scan_error(self, e: str) -> None:
        self._scan_worker = None
        self.status_label.setText(f"エラー: {e}")

    def on_open_in_browser(self) -> None:
        url = self.target_input.text().strip()
        if not url:
            self.status_label.setText("ターゲットを入力してください")
            return
        self.load_in_browser_requested.emit(url)

    def _on_path_selected(self) -> None:
        rows = self.paths_table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        url_item = self.paths_table.item(row, 0)
        if url_item:
            self.load_in_browser_requested.emit(url_item.text())

    def _toggle_options(self) -> None:
        # The options box is the previous widget added before status label
        # Easier: keep reference by name
        opts_box: QGroupBox = self.findChild(QGroupBox, "スキャンオプション") or None  # type: ignore
        # We set objectName below for reliability
        for w in self.findChildren(QGroupBox):
            if w.title() == "スキャンオプション":
                opts_box = w
                break
        if not opts_box:
            return
        vis = not opts_box.isVisible()
        opts_box.setVisible(vis)
        self.opts_toggle.setText("スキャンオプションを隠す" if vis else "スキャンオプションを表示")
        self.opts_toggle.setArrowType(Qt.ArrowType.DownArrow if vis else Qt.ArrowType.RightArrow)

    def _toggle_auth(self) -> None:
        vis = not self.auth_box.isVisible()
        self.auth_box.setVisible(vis)
        self.auth_toggle.setText("認証を隠す" if vis else "認証を表示")
        self.auth_toggle.setArrowType(Qt.ArrowType.DownArrow if vis else Qt.ArrowType.RightArrow)

    def _toggle_alt(self) -> None:
        vis = not self.alt_box.isVisible()
        self.alt_box.setVisible(vis)
        self.alt_toggle.setText("比較用アカウントを隠す" if vis else "比較用アカウントを表示")
        self.alt_toggle.setArrowType(Qt.ArrowType.DownArrow if vis else Qt.ArrowType.RightArrow)

    def _auth_config(self) -> AuthConfig:
        cfg = AuthConfig(
            login_url=self.login_url_input.text().strip() or None,
            username=self.username_input.text().strip() or None,
            password=self.password_input.text() or None,
        )
        return cfg

    def _alt_auth_config(self) -> AuthConfig | None:
        login = self.alt_login_url_input.text().strip()
        user = self.alt_username_input.text().strip()
        pwd = self.alt_password_input.text()
        if not (login and user and pwd):
            return None
        return AuthConfig(login_url=login, username=user, password=pwd)

    def _emit_auth_changed(self) -> None:
        self.auth_config_changed.emit(self._auth_config(), self.share_ai_checkbox.isChecked())

    def on_login_try(self) -> None:
        base = self.target_input.text().strip()
        cfg = self._auth_config()
        if not (base and cfg.login_url and cfg.username and cfg.password):
            self.status_label.setText("ターゲット/ログインURL/認証情報を入力してください")
            return
        self.status_label.setText("ログイン試行中…")
        worker = login_worker(base, cfg)
        self._login_worker = worker
        def _done(_):
            self._login_worker = None
            self.status_label.setText("ログイン試行完了")
        def _err(e: str):
            self._login_worker = None
            self.status_label.setText(f"エラー: {e}")
        worker.signals.result.connect(_done)
        worker.signals.error.connect(_err)
        worker.signals.progress.connect(lambda t: self.status_label.setText(str(t)))
        self.thread_pool.start(worker)

    def _scan_options(self) -> ScanOptions:
        xss = XSSOptions(
            enabled=self.xss_enable.isChecked(),
            param_name=self.xss_param.text().strip() or "q",
            payload=self.xss_payload.text(),
            success_tokens=[t.strip() for t in self.xss_tokens.text().split(",") if t.strip()],
        )
        sqli = SQLIOptions(
            enabled=self.sqli_enable.isChecked(),
            param_name=self.sqli_param.text().strip() or "id",
            baseline_value=self.sqli_baseline.text().strip() or "1",
            injection_template=self.sqli_template.text().strip() or "1",
        )
        opts = ScanOptions(xss=xss, sqli=sqli)
        opts.upload.enabled = self.upload_enable.isChecked()
        # OSコマンド注入（攻撃モード向け）
        # UIトグルはまた追加予定。現状は無効のまま。
        return opts
