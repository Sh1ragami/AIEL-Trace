from __future__ import annotations

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QDockWidget,
)
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from PySide6.QtWidgets import QStyle
from PySide6.QtGui import QAction

from mbsd_tool.gui.scan_controls import ScanControls
from mbsd_tool.gui.webview_panel import AgentBrowserPanel
from mbsd_tool.gui.results_panel import ResultsPanel
from mbsd_tool.core.models import ScanResult


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MBSDツール — 脆弱性診断")
        self.resize(1200, 800)

        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)
        self.tabs.setDocumentMode(True)

        # Panels
        self.scan_controls = ScanControls()
        self.agent_browser = AgentBrowserPanel()
        self.results_panel = ResultsPanel()

        # Wire up signals
        self.scan_controls.load_in_browser_requested.connect(self._on_open_in_browser)
        self.scan_controls.scan_completed.connect(self._on_scan_completed)
        self.scan_controls.auth_config_changed.connect(
            lambda cfg, share: self.agent_browser.set_auth_config(cfg, share)
        )
        self.scan_controls.deep_scan_requested.connect(self.agent_browser.start_deep_scan)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.addWidget(self.tabs)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setCentralWidget(container)

        # Dockable Agent Browser on the right (movable to left, resizable)
        self.agent_dock = QDockWidget("エージェントブラウザ", self)
        self.agent_dock.setWidget(self.agent_browser)
        self.agent_dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        self.agent_dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable | QDockWidget.DockWidgetClosable)
        self.addDockWidget(Qt.RightDockWidgetArea, self.agent_dock)
        # 初期幅を確保
        try:
            self.resizeDocks([self.agent_dock], [self.width() // 2], Qt.Horizontal)
        except Exception:
            pass

        # メニューに表示切替を追加
        view_menu = self.menuBar().addMenu("表示")
        toggle_action = self.agent_dock.toggleViewAction()
        toggle_action.setText("エージェントブラウザ")
        view_menu.addAction(toggle_action)

        # テーマ切替
        theme_menu = view_menu.addMenu("テーマ")
        self.act_theme_light = QAction("ライト", self, checkable=True)
        self.act_theme_dark = QAction("ダーク", self, checkable=True)
        self.act_theme_light.setChecked(True)
        self.act_theme_light.triggered.connect(lambda: self.apply_theme("light"))
        self.act_theme_dark.triggered.connect(lambda: self.apply_theme("dark"))
        theme_menu.addAction(self.act_theme_light)
        theme_menu.addAction(self.act_theme_dark)

        scan_ic = self.style().standardIcon(QStyle.SP_DialogOpenButton)
        results_ic = self.style().standardIcon(QStyle.SP_FileDialogDetailedView)
        self.tabs.addTab(self.scan_controls, scan_ic, "ターゲット/スキャン")
        self.tabs.addTab(self.results_panel, results_ic, "結果/レポート")

        # Show dock only on Scan tab
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self._on_tab_changed(self.tabs.currentIndex())
        self._last_scan_result: ScanResult | None = None
        # Start polling for deep-scan results merged from agent browser
        self._poll_id = self.startTimer(1000)

    def _on_scan_completed(self, result: ScanResult) -> None:
        self._last_scan_result = result
        self.results_panel.update_results(result)
        self.tabs.setCurrentWidget(self.results_panel)

    def _on_tab_changed(self, index: int) -> None:
        current = self.tabs.widget(index)
        show = current is self.scan_controls
        self.agent_dock.setVisible(show)

    def _on_open_in_browser(self, url: str) -> None:
        # Ensure dock is visible and load URL
        self.agent_dock.setVisible(True)
        self.tabs.setCurrentWidget(self.scan_controls)
        self.agent_browser.load_url(url)

    def timerEvent(self, event) -> None:  # type: ignore[override]
        # Poll AgentBrowserPanel for deep scan completion; it stores result temporarily
        res = getattr(self.agent_browser, "_last_deep_result", None)
        if res is not None:
            # clear and merge
            setattr(self.agent_browser, "_last_deep_result", None)
            merged = self._merge_results(self._last_scan_result, res)
            self._last_scan_result = merged
            self.results_panel.update_results(merged)
            self.tabs.setCurrentWidget(self.results_panel)
        super().timerEvent(event)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        try:
            self.killTimer(self._poll_id)
        except Exception:
            pass
        super().closeEvent(event)

    def _merge_results(self, base: ScanResult | None, extra: ScanResult) -> ScanResult:
        if base is None:
            return extra
        endpoints = list(dict.fromkeys(base.endpoints + extra.endpoints))
        vulns = dict(base.vulns_by_endpoint)
        for k, lst in extra.vulns_by_endpoint.items():
            vulns.setdefault(k, []).extend(lst)
        return ScanResult(target=base.target or extra.target, mode=base.mode, endpoints=endpoints, vulns_by_endpoint=vulns)

    def apply_theme(self, mode: str) -> None:
        # Simple QSS-based theme switcher for light/dark
        app = QApplication.instance()
        if not app:
            return
        if mode == "dark":
            self.act_theme_dark.setChecked(True)
            self.act_theme_light.setChecked(False)
            qss = """
            QWidget { color: #e6e6e6; background: #2b2b2b; }
            QLineEdit, QComboBox, QTableWidget, QGroupBox { background: #3a3a3a; border: 1px solid #555; }
            QPushButton { background: #444; border: 1px solid #666; padding: 6px 10px; }
            QPushButton:hover { background: #555; }
            QProgressBar { background: #3a3a3a; border: 1px solid #555; border-radius: 4px; text-align: center; }
            QProgressBar::chunk { background-color: #2c4f73; }
            QTabWidget::pane { border-top: 1px solid #555; }
            QHeaderView::section { background: #3a3a3a; color: #ddd; }
            QMenu { background: #333; color: #eee; }
            QDockWidget::title { background: #333; color: #ddd; padding: 4px; }
            """
            app.setStyleSheet(qss)
            # Chart theme反映
            try:
                self.results_panel.set_theme("dark")
                self.scan_controls.apply_theme("dark")
            except Exception:
                pass
        else:
            self.act_theme_light.setChecked(True)
            self.act_theme_dark.setChecked(False)
            qss = """
            QWidget { color: #222; background: #fafafa; }
            QLineEdit, QComboBox, QTableWidget, QGroupBox { background: #ffffff; border: 1px solid #ccc; }
            QPushButton { background: #f0f0f0; border: 1px solid #ccc; padding: 6px 10px; }
            QPushButton:hover { background: #e6e6e6; }
            QProgressBar { background: #ffffff; border: 1px solid #ccc; border-radius: 4px; text-align: center; }
            QProgressBar::chunk { background-color: #1976d2; }
            QTabWidget::pane { border-top: 1px solid #ccc; }
            QHeaderView::section { background: #f0f0f0; color: #222; }
            QMenu { background: #fff; color: #222; }
            QDockWidget::title { background: #f0f0f0; color: #222; padding: 4px; }
            """
            app.setStyleSheet(qss)
            try:
                self.results_panel.set_theme("light")
                self.scan_controls.apply_theme("light")
            except Exception:
                pass
