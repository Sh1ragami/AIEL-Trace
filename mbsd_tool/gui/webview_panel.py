from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QTimer, QPoint, QPropertyAnimation, QEasingCurve, QUrl
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QSizePolicy
from PySide6.QtWebEngineWidgets import QWebEngineView

from mbsd_tool.core.agent import AgentClient
from mbsd_tool.config.settings import Settings
from mbsd_tool.core.models import AuthConfig


class CursorOverlay(QWidget):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_NoSystemBackground)
        self.setStyleSheet("background: transparent;")
        self.dot = QLabel(self)
        self.dot.setStyleSheet(
            "border-radius: 6px; background: rgba(0, 120, 215, 0.9); width: 12px; height: 12px;"
        )
        self.dot.resize(12, 12)
        self._anim = QPropertyAnimation(self.dot, b"pos", self)
        self._anim.setDuration(400)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def move_to(self, x: int, y: int) -> None:
        self._anim.stop()
        self._anim.setEndValue(QPoint(x - 6, y - 6))
        self._anim.start()

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)


class AgentBrowserPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.web = QWebEngineView()
        self.status = QLabel("エージェント待機中")
        layout = QVBoxLayout(self)
        layout.addWidget(self.web)
        # ステータスはUIに表示しない（表示領域を最大化）
        # layout.addWidget(self.status)

        # ブラウザ領域を最大化するサイズポリシー
        self.web.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.overlay = CursorOverlay(self.web)
        self.overlay.setGeometry(self.web.rect())
        self.overlay.raise_()
        self.web.resizeEvent = self._wrap_resize(self.web.resizeEvent)  # type: ignore

        self.agent: Optional[AgentClient] = None
        self.timer = QTimer(self)
        self.timer.setInterval(2500)
        self.timer.timeout.connect(self._tick)

        self.settings = Settings.load()
        self._auth: AuthConfig | None = None
        self._share_auth_with_ai: bool = False
        self._login_attempted: bool = False

    def _wrap_resize(self, original):
        def handler(event):
            original(event)
            self.overlay.setGeometry(self.web.rect())
        return handler

    def load_url(self, url: str) -> None:
        self.web.setUrl(QUrl(url))
        self.status.setText(f"読み込み完了: {url}")
        if self.agent is None:
            self.agent = AgentClient(self.settings.ollama_base_url, self.settings.ollama_model)
        self.timer.start()
        self._login_attempted = False

    def _tick(self) -> None:
        # Fetch DOM snapshot and ask the agent for the next action.
        def _on_html(html: str) -> None:
            if not self.agent:
                return
            # Simple auto-login heuristic (one-time) if credentials are provided
            if (
                not self._login_attempted
                and self._auth
                and self._auth.username
                and self._auth.password
                and ("type=\"password\"" in html or "type=\'password\'" in html)
            ):
                uname = self._auth.username.replace("\\", "\\\\").replace("'", "\\'")
                pwd = self._auth.password.replace("\\", "\\\\").replace("'", "\\'")
                js_login = f"""
                (function(){{
                  var pwd=document.querySelector('input[type="password"]');
                  if(!pwd) return 'no-pwd';
                  var form=pwd.form; if(!form) return 'no-form';
                  var u=form.querySelector('input[type="text"],input[type="email"],input[name*="user"],input[name*="email"],input[name*="login"]');
                  if(u) u.value='{uname}';
                  pwd.value='{pwd}';
                  var btn=form.querySelector('button[type="submit"],input[type="submit"]');
                  if(btn){{btn.click();}} else {{form.submit();}}
                  return 'ok';
                }})();
                """
                self.web.page().runJavaScript(js_login)
                self._login_attempted = True
                self.status.setText("自動ログインを試行")
            try:
                action = self.agent.decide_next_action(
                    html,
                    auth=self._auth if self._share_auth_with_ai else None,
                )
            except Exception as e:
                self.status.setText(f"エージェントエラー: {e}")
                return
            # Apply a very simple action set: move cursor, click first link if asked
            if action and action.get("type") == "move_click":
                x = int(action.get("x", 100))
                y = int(action.get("y", 100))
                self.overlay.move_to(x, y)
                # Click via DOM event at given coordinates
                js = f"(function(){{ var el = document.elementFromPoint({x}, {y}); if(el) el.click(); }})();"
                self.web.page().runJavaScript(js)
                self.status.setText("エージェントがクリック")
            elif action and action.get("type") == "navigate":
                href = action.get("url")
                if href:
                    self.web.page().runJavaScript(f"window.location.href = '{href}';")
                    self.status.setText(f"エージェントが遷移 -> {href}")
            else:
                # Move cursor only
                x = int(action.get("x", 80) if action else 80)
                y = int(action.get("y", 80) if action else 80)
                self.overlay.move_to(x, y)
                self.status.setText("エージェントがカーソル移動")

        self.web.page().toHtml(_on_html)

    def set_auth_config(self, cfg: AuthConfig, share_with_ai: bool) -> None:
        self._auth = cfg
        self._share_auth_with_ai = share_with_ai
