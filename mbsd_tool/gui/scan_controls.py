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
    QListWidget,
    QLabel,
    QGroupBox,
    QCheckBox,
)

from mbsd_tool.core.enumerator import enumerate_paths_worker
from mbsd_tool.core.scanner import scan_targets_worker
from mbsd_tool.core.models import ScanMode, ScanResult, AuthConfig
from mbsd_tool.core.auth import login_worker


class ScanControls(QWidget):
    load_in_browser_requested = Signal(str)
    scan_completed = Signal(ScanResult)
    auth_config_changed = Signal(AuthConfig, bool)

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

        self.open_in_browser_btn = QPushButton("エージェントブラウザで開く")
        self.open_in_browser_btn.clicked.connect(self.on_open_in_browser)

        self.status_label = QLabel("待機中")

        self.paths_list = QListWidget()

        top_form = QFormLayout()
        top_form.addRow("ターゲット", self.target_input)
        top_form.addRow("モード", self.mode_combo)

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

        auth_box = QGroupBox("認証")
        auth_form = QFormLayout()
        auth_form.addRow("ログインURL", self.login_url_input)
        auth_form.addRow("ユーザー名/メール", self.username_input)
        auth_form.addRow("パスワード", self.password_input)
        auth_form.addRow("", self.login_btn)
        auth_form.addRow("", self.share_ai_checkbox)
        auth_box.setLayout(auth_form)

        btns = QHBoxLayout()
        btns.addWidget(self.enumerate_btn)
        btns.addWidget(self.scan_btn)
        btns.addWidget(self.open_in_browser_btn)
        btns.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addLayout(top_form)
        layout.addWidget(auth_box)
        layout.addLayout(btns)
        layout.addWidget(QLabel("検出されたパス"))
        layout.addWidget(self.paths_list)
        layout.addWidget(self.status_label)

        self.discovered_urls: List[str] = []
        # propagate auth config initially
        self._emit_auth_changed()

    def on_enumerate(self) -> None:
        base = self.target_input.text().strip()
        if not base:
            self.status_label.setText("ターゲットを入力してください")
            return
        self.paths_list.clear()
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
        for u in urls:
            self.paths_list.addItem(u)
        self.scan_btn.setEnabled(len(urls) > 0)
        self.status_label.setText(f"{len(urls)}件のエンドポイントを検出")

    def _on_enum_error(self, e: str) -> None:
        self._enum_worker = None
        self.status_label.setText(f"エラー: {e}")

    def on_scan(self) -> None:
        if not self.discovered_urls:
            self.status_label.setText("スキャン対象がありません")
            return
        mode = ScanMode(self.mode_combo.currentText())
        self.status_label.setText("スキャン中…")

        worker = scan_targets_worker(self.discovered_urls, mode, self._auth_config())
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

    def _auth_config(self) -> AuthConfig:
        cfg = AuthConfig(
            login_url=self.login_url_input.text().strip() or None,
            username=self.username_input.text().strip() or None,
            password=self.password_input.text() or None,
        )
        return cfg

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
