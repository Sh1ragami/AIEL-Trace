from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QTimer, QPoint, QPropertyAnimation, QEasingCurve, QUrl
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QSizePolicy, QTabWidget, QPlainTextEdit
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineScript

from mbsd_tool.core.agent import AgentClient
from mbsd_tool.config.settings import Settings
from mbsd_tool.core.models import AuthConfig
from mbsd_tool.core.models import VulnerabilityFinding, ScanResult, ScanMode
from mbsd_tool.gui.highlighters import HtmlHighlighter


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


class TestWebPage(QWebEnginePage):
    def __init__(self, panel: 'AgentBrowserPanel') -> None:
        super().__init__(panel)
        self.panel = panel

    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):  # type: ignore[override]
        msg = str(message)
        if msg.startswith('MBSD_SINK:'):
            self.panel._on_sink_event(msg)
        return super().javaScriptConsoleMessage(level, message, lineNumber, sourceID)


class AgentBrowserPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.web = QWebEngineView()
        self.page = TestWebPage(self)
        self.web.setPage(self.page)
        self.status = QLabel("エージェント待機中")
        self.view_tabs = QTabWidget()
        self.view_tabs.addTab(self.web, "表示")
        self.source_view = QPlainTextEdit(); self.source_view.setReadOnly(True)
        # Monospace + syntax highlight for HTML source
        try:
            mono = QFontDatabase.systemFont(QFontDatabase.FixedFont)  # type: ignore[attr-defined]
        except Exception:
            mono = QFont("Monospace")
            mono.setStyleHint(QFont.TypeWriter)
        mono.setPointSize(mono.pointSize() + 1)
        self.source_view.setFont(mono)
        self.source_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self._src_highlighter = HtmlHighlighter(self.source_view.document())
        self.view_tabs.addTab(self.source_view, "ソース")
        layout = QVBoxLayout(self)
        layout.addWidget(self.view_tabs)
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
        # Deep scan autopilot state
        self._deep_urls: list[str] = []
        self._deep_index: int = -1
        self._deep_phase: str = "idle"  # 'dom', 'fill', 'next'
        self._deep_findings: dict[str, list[VulnerabilityFinding]] = {}
        self._target_origin: str | None = None
        # Install sink hooks for DOM-based XSS observation
        self._install_sink_hooks()
        self._selector_to_highlight: Optional[str] = None
        self.web.loadFinished.connect(self._on_load_finished)

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
        # Track origin for report target
        try:
            u = QUrl(url)
            self._target_origin = f"{u.scheme()}://{u.host()}:{u.port()}" if u.port() != -1 else f"{u.scheme()}://{u.host()}"
        except Exception:
            pass

    def load_and_highlight(self, url: str, selector: str) -> None:
        """指定されたURLをロードし、ロード完了後に指定された要素をハイライトする"""
        self._selector_to_highlight = selector
        self.load_url(url)
        self.timer.stop() # 自動操縦タイマーを停止する

    def _on_load_finished(self, ok: bool) -> None:
        """ページのロード完了後にハイライト処理を実行する"""
        if not ok or not self._selector_to_highlight:
            return

        selector = self._selector_to_highlight.replace("'", "\\'")
        
        js_code = f"""
        (function() {{
            // 以前のハイライトを削除
            var highlighted = document.querySelector('.mbsd-highlighted');
            if (highlighted) {{
                highlighted.style.border = '';
                highlighted.style.outline = '';
                highlighted.classList.remove('mbsd-highlighted');
            }}

            var element = document.querySelector('{selector}');
            if (element) {{
                element.style.border = '3px solid red';
                element.style.outline = '2px solid rgba(255, 0, 0, 0.6)';
                element.classList.add('mbsd-highlighted');
                element.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
            }}
        }})();
        """
        self.web.page().runJavaScript(js_code)
        # ハイライト後にセレクタをクリア
        self._selector_to_highlight = None

    

    def _tick(self) -> None:
        # Fetch DOM snapshot and ask the agent for the next action.
        def _on_html(html: str) -> None:
            if not self.agent:
                return
            try:
                self.source_view.setPlainText(html)
            except Exception:
                pass
            # Deep-scan phases
            if self._deep_phase in ("dom", "fill") and self._deep_index >= 0 and self._deep_index < len(self._deep_urls):
                current = self._deep_urls[self._deep_index]
                if self._deep_phase == "dom":
                    # Check if MBSD_DOMXSS reflects in the DOM
                    if "mbsd_domxss" in html.lower() and "MBSD_DOMXSS" in html:
                        v = VulnerabilityFinding(
                            name="DOMベースXSSの可能性",
                            severity="中",
                            evidence="パラメータ 'mbsd_domxss' がDOMに反映",
                            reproduction_steps=[f"URLに ?mbsd_domxss=MBSD_DOMXSS を付与し表示"],
                            category="B XSS",
                            test_type="能動的",
                        )
                        self._record_finding(current, v)
                    # Move to fill phase: try to submit forms with marker for stored-XSS
                    js_fill = """
                    (function(){
                      var filled=false;
                      document.querySelectorAll('input[type="text"],textarea').forEach(function(el){
                        if(!filled){ el.value='MBSD_STORED_XSS'; filled=true;}
                      });
                      var f=document.querySelector('form'); if(f){
                        var b=f.querySelector('button[type="submit"],input[type="submit"]');
                        if(b){ b.click(); } else { f.submit(); }
                        return 'submitted';
                      }
                      return 'noform';
                    })();
                    """
                    self.web.page().runJavaScript(js_fill)
                    self._deep_phase = "fill"
                    self.status.setText("深度: フォーム送信試行")
                    return
                elif self._deep_phase == "fill":
                    # After navigation, check if MBSD_STORED_XSS appears
                    if "MBSD_STORED_XSS" in html:
                        v2 = VulnerabilityFinding(
                            name="格納型XSSの可能性",
                            severity="高",
                            evidence="投稿値 MBSD_STORED_XSS を表示で検出",
                            reproduction_steps=["フォームへ MBSD_STORED_XSS を入力し送信", "表示画面で文字列を確認"],
                            category="B XSS",
                            test_type="能動的",
                        )
                        self._record_finding(current, v2)
                    # Advance to next URL
                    self._deep_phase = "idle"
                    self._advance_deep()
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
                  var pwd=document.querySelector('input[type=\"password\"]');
                  if(!pwd) return 'no-pwd';
                  var form=pwd.form; if(!form) return 'no-form';
                  var u=form.querySelector('input[type=\"text\"],input[type=\"email\"],input[name*=\"user\"],input[name*=\"email\"],input[name*=\"login\"]');
                  if(u) u.value='{uname}';
                  pwd.value='{pwd}';
                  var btn=form.querySelector('button[type=\"submit\"],input[type=\"submit\"]');
                  if(btn){{btn.click();}} else {{form.submit();}}\n                  return 'ok';
                }})();// end IIFE
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
            elif action and action.get("type") == "fill_and_submit":
                fields = action.get("fields") or {}
                # Fill by name/id and submit the first form
                kv_js_entries = []
                for k, v in fields.items():
                    key = str(k).replace("'", "\\'")
                    val = str(v).replace("'", "\\'")
                    kv_js_entries.append(f"['{key}','{val}']")
                kv_pairs = ",".join(kv_js_entries)
                js_fill = rf"""
                (function(){{
                  var kv= new Map([{kv_pairs}]);
                  kv.forEach(function(val,key){{
                    var esc = (window.CSS && CSS.escape) ? CSS.escape(key) : String(key).replace(/(['"\]])/g,'\$1');
                    var el=document.querySelector('[name='+esc+'],#'+esc);
                    if(el) el.value=val;
                  }});
                  var f=document.querySelector('form'); if(f){{
                    var b=f.querySelector('button[type="submit"],input[type="submit"]');
                    if(b){{ b.click(); }} else {{ f.submit(); }}
                    return 'submitted';
                  }}
                  return 'noform';
                }})();
                """
                self.web.page().runJavaScript(js_fill)
                self.status.setText("エージェントがフォーム送信")
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

    # Autopilot: deep scan sequence over URLs
    def start_deep_scan(self, urls: list[str]) -> None:
        self._deep_urls = urls
        self._deep_index = -1
        self._deep_phase = "idle"
        self._deep_findings = {}
        self._advance_deep()

    def _advance_deep(self) -> None:
        self._deep_index += 1
        if self._deep_index >= len(self._deep_urls):
            # Emit results as ScanResult-like
            endpoints = list(self._deep_findings.keys())
            result = ScanResult(
                target=self._target_origin or (self._deep_urls[0] if self._deep_urls else ""),
                mode=ScanMode.NORMAL,
                endpoints=endpoints,
                vulns_by_endpoint=self._deep_findings,
            )
            # Reuse scan_completed signal path by emitting via MainWindow connection
            # We'll use a custom Qt signal on MainWindow side, so keep state only here.
            # As a workaround, load an about:blank to stop interactions.
            self.web.setUrl(QUrl("about:blank"))
            # Store on object for MainWindow polling (or extend with a signal in future)
            self._last_deep_result = result  # type: ignore[attr-defined]
            self.status.setText("深度スキャン完了")
            return
        url = self._deep_urls[self._deep_index]
        # Phase 1: DOM reflection check
        from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
        try:
            pr = urlparse(url)
            q = dict(parse_qsl(pr.query))
            q["mbsd_domxss"] = "MBSD_DOMXSS"
            newq = urlencode(q)
            built = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, newq, pr.fragment))
        except Exception:
            built = url
        self._deep_phase = "dom"
        self.load_url(built)

    def _record_finding(self, endpoint: str, v: VulnerabilityFinding) -> None:
        self._deep_findings.setdefault(endpoint, []).append(v)

    def _install_sink_hooks(self) -> None:
        js = (
            "(function(){"
            "try {"
            "  var _a=window.alert; window.alert=function(m){console.log('MBSD_SINK:alert:'+m); return _a.apply(this, arguments);};"
            "} catch(e) {}"
            "try {"
            "  var _w=document.write; document.write=function(m){console.log('MBSD_SINK:document.write:'+m); return _w.apply(this, arguments);};"
            "} catch(e) {}"
            "try {"
            "  var _e=window.eval; window.eval=function(m){console.log('MBSD_SINK:eval:'+m); return _e.apply(this, arguments);};"
            "} catch(e) {}"
            "try {"
            "  var _ih=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');"
            "  if(_ih && _ih.set){"
            "    Object.defineProperty(Element.prototype,'innerHTML',{set:function(v){console.log('MBSD_SINK:innerHTML:'+String(v)); return _ih.set.call(this, v);}});"
            "  }"
            "} catch(e) {}"
            "})();"
        )
        script = QWebEngineScript()
        try:
            script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)  # type: ignore[attr-defined]
            script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)  # type: ignore[attr-defined]
        except Exception:
            # Fallback constants on some PySide6 versions
            script.setInjectionPoint(0)
            script.setWorldId(0)
        script.setName("mbsd_sink_hooks")
        script.setSourceCode(js)
        try:
            self.web.page().scripts().insert(script)
        except Exception:
            try:
                self.web.page().profile().scripts().insert(script)
            except Exception:
                pass

    def _on_sink_event(self, msg: str) -> None:
        if self._deep_index < 0 or self._deep_index >= len(self._deep_urls):
            return
        cur = self._deep_urls[self._deep_index]
        v = VulnerabilityFinding(
            name="DOMベースXSSの可能性（シンク検出）",
            severity="中",
            evidence=msg,
            reproduction_steps=["ページ操作中にJSシンク関数呼び出しを検出"],
            category="B XSS",
            test_type="能動的",
        )
        self._record_finding(cur, v)
