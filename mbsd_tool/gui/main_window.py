from __future__ import annotations

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QDockWidget,
)
from PySide6.QtCore import Qt

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
        self.scan_controls.load_in_browser_requested.connect(self.agent_browser.load_url)
        self.scan_controls.scan_completed.connect(self._on_scan_completed)
        self.scan_controls.auth_config_changed.connect(
            lambda cfg, share: self.agent_browser.set_auth_config(cfg, share)
        )

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

        self.tabs.addTab(self.scan_controls, "ターゲット/スキャン")
        self.tabs.addTab(self.results_panel, "結果/レポート")

        # Show dock only on Scan tab
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self._on_tab_changed(self.tabs.currentIndex())

    def _on_scan_completed(self, result: ScanResult) -> None:
        self.results_panel.update_results(result)
        self.tabs.setCurrentWidget(self.results_panel)

    def _on_tab_changed(self, index: int) -> None:
        current = self.tabs.widget(index)
        show = current is self.scan_controls
        self.agent_dock.setVisible(show)
