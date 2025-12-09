from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

import httpx

from mbsd_tool.core.models import ScanMode, VulnerabilityFinding, ScanResult, AuthConfig, ScanOptions
from mbsd_tool.core.utils import FunctionWorker
from mbsd_tool.core.auth import try_login
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from mbsd_tool.config.settings import Settings
from mbsd_tool.core.logic_analyzer import LogicAnalyzer


SEC_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

# Common error signatures for noisy error disclosure detection
ERROR_SIGNS = [
    "traceback (most recent call last)",
    "stack trace",
    "exception:",
    "fatal error",
    "notice:",
    "warning:",
    "undefined index",
    "undefined variable",
]


def _passive_checks(url: str, resp: httpx.Response) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    # セキュリティヘッダの欠如
    missing = [h for h in SEC_HEADERS if h not in resp.headers]
    if missing:
        findings.append(
            VulnerabilityFinding(
                name="セキュリティヘッダの欠如",
                severity="中",
                evidence=", ".join(missing),
                reproduction_steps=[f"GET {url}", "レスポンスヘッダを確認"],
                category="その他",
                test_type="受動的",
                explanation="クリックジャッキングやMIMEスニッフィング等に対する主要ヘッダが未設定です。",
                remediation="CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy を適切に設定してください。"
            )
        )
    # ディレクトリ・リスティング
    ct = resp.headers.get("content-type", "")
    if resp.status_code == 200 and "text/html" in ct and "Index of /" in resp.text:
        findings.append(
            VulnerabilityFinding(
                name="ディレクトリ・リスティング",
                severity="中",
                evidence="ページに 'Index of /' を検出",
                reproduction_steps=[f"GET {url}", "インデックス表示を確認"],
                category="E ディレクトリ・リスティング",
                test_type="受動的",
                explanation="ウェブサーバのディレクトリ一覧が外部から閲覧可能です。内部ファイルが露出します。",
                remediation="サーバ設定でディレクトリリスティングを無効化し、公開不要なファイルは配置しないでください。"
            )
        )
    # 技術情報の露出
    powered = resp.headers.get("x-powered-by") or resp.headers.get("server")
    if powered:
        findings.append(
            VulnerabilityFinding(
                name="技術情報の露出",
                severity="低",
                evidence=f"Header: {powered}",
                reproduction_steps=[f"GET {url}", "'Server'/'X-Powered-By' を確認"],
                category="その他",
                test_type="受動的",
                explanation="サーバ製品名やバージョン等の情報がヘッダから判別可能です。攻撃の足掛かりになります。",
                remediation="不要なヘッダを削除/マスキングし、バナー情報の露出を抑制してください。"
            )
        )
    # CSRF対策（簡易）: POSTフォームにCSRFトークンが見当たらない
    if resp.status_code == 200 and "text/html" in ct:
        try:
            soup = BeautifulSoup(resp.text, "lxml")
            for form in soup.find_all("form"):
                method = (form.get("method") or "get").lower()
                if method != "post":
                    continue
                tokens = form.find_all("input", attrs={"type": "hidden"})
                names = [(i.get("name") or i.get("id") or "").lower() for i in tokens]
                if not any("csrf" in n or "token" in n for n in names):
                    findings.append(
                        VulnerabilityFinding(
                            name="CSRF対策不明",
                            severity="中",
                            evidence="POSTフォームにCSRFトークンが見当たらない",
                            reproduction_steps=[f"GET {url}", "フォームHTMLを確認"],
                            category="C CSRF",
                            test_type="受動的",
                            explanation="CSRFトークンが確認できず、他サイトからの自動送信で意図しない操作が成立する恐れがあります。",
                            remediation="フォーム送信にCSRFトークンを必須化し、SameSite Cookie・Origin/Referer 検証と併用してください。"
                        )
                    )
                    break
        except Exception:
            pass
    # Sensitive file exposures
    lower_url = url.lower()
    if "/.git/" in lower_url:
        findings.append(
            VulnerabilityFinding(
                name="Gitリポジトリの露出",
                severity="高",
                evidence=f"{url}",
                reproduction_steps=[f"GET {url}", "機密情報（リビジョン/設定）取得可能"],
                category="情報漏えい",
                test_type="受動的",
                explanation=".git 配下が公開されており、履歴や設定など機密情報が取得可能です。",
                remediation=".git ディレクトリを公開領域から除外し、サーバ設定でアクセスを拒否してください。"
            )
        )
    if lower_url.endswith("/.env"):
        if any(k in resp.text for k in ["APP_KEY", "DB_PASSWORD", "DATABASE_URL", "SECRET_KEY"]):
            findings.append(
                VulnerabilityFinding(
                    name="環境変数ファイルの露出 (.env)",
                    severity="高",
                    evidence="機密キー/DB情報を含む可能性",
                    reproduction_steps=[f"GET {url}", "内容を確認"],
                    category="情報漏えい",
                    test_type="受動的",
                    explanation="環境変数ファイルが公開されており、秘密鍵やDB資格情報が漏洩する恐れがあります。",
                    remediation=".env などの設定ファイルは公開領域に置かず、アクセス制御を徹底してください。"
                )
            )
    if lower_url.endswith(".sql") or any(s in resp.text for s in ["CREATE TABLE", "INSERT INTO", "DROP TABLE"]):
        findings.append(
            VulnerabilityFinding(
                name="DBダンプの露出",
                severity="高",
                evidence="SQLスキーマやデータが含まれる",
                reproduction_steps=[f"GET {url}", "レスポンスを確認"],
                category="情報漏えい",
                test_type="受動的",
                explanation="データベースの内容がダンプとして公開され、個人情報等の漏洩につながります。",
                remediation="バックアップファイルを公開領域に配置しないでください。必要なら認証下で保護してください。"
            )
        )
    if lower_url.endswith(".map") or "sourceMappingURL" in resp.text:
        findings.append(
            VulnerabilityFinding(
                name="ソースマップの露出",
                severity="低",
                evidence=".mapによりソース構造が開示",
                reproduction_steps=[f"GET {url}", ".mapの内容を確認"],
                category="情報漏えい",
                test_type="受動的",
                explanation=".map により難読化前のソース構造が推測可能です。",
                remediation="本番環境ではソースマップの公開を停止してください。"
            )
        )
    for suf in ["~", ".bak", ".old", ".orig", ".backup", ".save", ".bkp", ".tmp", ".zip", ".tar.gz", ".swp"]:
        if lower_url.endswith(suf):
            findings.append(
                VulnerabilityFinding(
                    name="バックアップ/一時ファイルの露出",
                    severity="中",
                    evidence=f"サフィックス: {suf}",
                    reproduction_steps=[f"GET {url}", "不要ファイルの公開を確認"],
                    category="情報漏えい",
                    test_type="受動的",
                    explanation="バックアップや一時ファイルが公開領域に残存しています。",
                    remediation="運用・デプロイ時に不要ファイルを除去し、機密情報を含むものは公開しないでください。"
                )
            )
    # CORSミスコンフィグ: ACAO=*, 且つ Credentials=true
    aco = resp.headers.get("access-control-allow-origin", "")
    acc = resp.headers.get("access-control-allow-credentials", "").lower()
    if aco.strip() == "*" and acc == "true":
        findings.append(
            VulnerabilityFinding(
                name="CORSミスコンフィグ",
                severity="中",
                evidence="Access-Control-Allow-Origin: * かつ Allow-Credentials: true",
                reproduction_steps=[f"GET {url}", "レスポンスヘッダを確認"],
                category="I HTTPヘッダ",
                test_type="受動的",
            )
        )
    # HSTS 未設定（HTTPSのとき）
    try:
        parsed = urlparse(url)
        if parsed.scheme == "https":
            if "strict-transport-security" not in resp.headers:
                findings.append(
                    VulnerabilityFinding(
                        name="HSTS未設定",
                        severity="低",
                        evidence="Strict-Transport-Security ヘッダなし",
                        reproduction_steps=[f"GET {url}", "レスポンスヘッダを確認"],
                        category="I HTTPヘッダ",
                        test_type="受動的",
                        remediation="HTTPS運用時はHSTSを有効化し、max-age を十分な値に設定してください。"
                    )
                )
    except Exception:
        pass
    # Cookie属性の不備（Set-Cookie から）
    try:
        sc_all = []
        get_list = getattr(resp.headers, "get_list", None)
        if callable(get_list):
            sc_all = resp.headers.get_list("set-cookie")
        else:
            v = resp.headers.get("set-cookie")
            if v:
                sc_all = [v]
        for sc in sc_all:
            scl = sc.lower()
            is_session = any(k in scl for k in ["sess", "phpsessid", "jsessionid"]) or ("session" in scl)
            if is_session:
                if "httponly" not in scl:
                    findings.append(
                        VulnerabilityFinding(
                            name="セッションクッキーにHttpOnly未設定",
                            severity="中",
                            evidence=sc,
                            reproduction_steps=[f"GET {url}", "Set-Cookie 属性を確認"],
                            category="K セッション/認証",
                            test_type="受動的",
                            remediation="セッションCookieに HttpOnly を付与してください。"
                        )
                    )
                if url.lower().startswith("https://") and ("secure" not in scl):
                    findings.append(
                        VulnerabilityFinding(
                            name="セッションクッキーにSecure未設定",
                            severity="中",
                            evidence=sc,
                            reproduction_steps=[f"GET {url}", "Set-Cookie 属性を確認"],
                            category="K セッション/認証",
                            test_type="受動的",
                            remediation="HTTPS配信ではセッションCookieに Secure を付与してください。"
                        )
                    )
                if "samesite" not in scl:
                    findings.append(
                        VulnerabilityFinding(
                            name="セッションクッキーにSameSite未設定",
                            severity="低",
                            evidence=sc,
                            reproduction_steps=[f"GET {url}", "Set-Cookie 属性を確認"],
                            category="K セッション/認証",
                            test_type="受動的",
                            remediation="SameSite=Lax 以上の設定を推奨します。"
                        )
                    )
    except Exception:
        pass
    # クリックジャッキングの可能性: XFO/CSPのframe-ancestorsなし
    csp = resp.headers.get("content-security-policy", "").lower()
    xfo = resp.headers.get("x-frame-options", "").lower()
    if ("frame-ancestors" not in csp) and (xfo not in ("deny", "sameorigin")):
        findings.append(
            VulnerabilityFinding(
                name="クリックジャッキングの可能性",
                severity="中",
                evidence="X-Frame-Options/CSP frame-ancestors 不備",
                reproduction_steps=[f"GET {url}", "ヘッダを確認"],
                category="その他",
                test_type="受動的",
            )
        )
    # ファイルアップロード機能の存在（受動的）
    if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
        try:
            soup2 = BeautifulSoup(resp.text, "lxml")
            file_inputs = soup2.find_all("input", attrs={"type": "file"})
            if file_inputs:
                accept_attrs = [fi.get("accept") for fi in file_inputs if fi.get("accept")]
                note = "拡張子制限: 不明"
                if accept_attrs:
                    note = f"拡張子制限: {', '.join(accept_attrs)}"
                findings.append(
                    VulnerabilityFinding(
                        name="ファイルアップロード機能の存在",
                        severity="情報",
                        evidence=f"input[type=file] が {len(file_inputs)} 箇所",
                        reproduction_steps=[f"GET {url}", "フォームにファイル入力を確認"],
                        category="アップロード",
                        test_type="受動的",
                        notes=note,
                    )
                )
        except Exception:
            pass
    # 入力値検証（クライアント側）の不備（required/pattern が見当たらない）
    if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
        try:
            soup = BeautifulSoup(resp.text, "lxml")
            inputs = soup.find_all("input")
            text_like = [i for i in inputs if (i.get("type") or "text").lower() in ("text", "email", "number", "search", "tel")]
            if text_like:
                weak = [i for i in text_like if not i.has_attr("required") and not i.has_attr("pattern")]
                if len(weak) == len(text_like):
                    findings.append(
                        VulnerabilityFinding(
                            name="入力値検証の不備（クライアント側）",
                            severity="低",
                            evidence="input に required/pattern が見当たらない",
                            reproduction_steps=[f"GET {url}", "フォームのinput属性を確認"],
                            category="入力",
                            test_type="受動的",
                        )
                    )
        except Exception:
            pass
    # デバッグ機能の残存（簡易）
    if resp.headers.get("x-debug-token") or "_debugbar" in resp.text.lower():
        findings.append(
            VulnerabilityFinding(
                name="デバッグ機能の残存",
                severity="中",
                evidence="X-Debug-Token ヘッダ / debugbar 痕跡",
                reproduction_steps=[f"GET {url}", "レスポンスヘッダ/スクリプトを確認"],
                category="サイトデザイン",
                test_type="受動的",
            )
        )

    # クリプトジャッキングの疑い: 既知キーワード
    if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
        try:
            soup = BeautifulSoup(resp.text, "lxml")
            scripts = "\n".join([s.get_text("\n") or "" for s in soup.find_all("script")])
            srcs = "\n".join([s.get("src") or "" for s in soup.find_all("script")])
            blob = (scripts + "\n" + srcs).lower()
            indicators = ["coinhive", "webmine", "cryptonight", "miner", "wasm", "instantiateStreaming"]
            if any(ind in blob for ind in indicators):
                findings.append(
                    VulnerabilityFinding(
                        name="クリプトジャッキングの可能性",
                        severity="中",
                        evidence="マイニング関連のキーワードを検出",
                        reproduction_steps=[f"GET {url}", "script/src内の文字列を確認"],
                        category="M クローラ耐性/その他",
                        test_type="受動的",
                    )
                )
        except Exception:
            pass
    # パスワード入力のautocomplete不足
    if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
        try:
            soup3 = BeautifulSoup(resp.text, "lxml")
            pwds = soup3.find_all("input", attrs={"type": "password"})
            for p in pwds:
                ac = (p.get("autocomplete") or "").lower()
                if ac not in ("new-password", "current-password"):
                    findings.append(
                        VulnerabilityFinding(
                            name="パスワードのオートコンプリートの不備",
                            severity="低",
                            evidence=f"autocomplete='{ac or '未指定'}'",
                            reproduction_steps=[f"GET {url}", "password入力のautocomplete属性を確認"],
                            category="K セッション/認証",
                            test_type="受動的",
                        )
                    )
                    break
        except Exception:
            pass
    # ブルートフォース/クレデンシャルスタッフィング対策不明（CAPTCHA等が見当たらない）
    if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
        try:
            html_lower = resp.text.lower()
            has_pwd = "type=\"password\"" in html_lower or "type='password'" in html_lower
            if has_pwd and not any(x in html_lower for x in ["captcha", "recaptcha", "hcaptcha"]):
                findings.append(
                    VulnerabilityFinding(
                        name="ブルートフォース/クレデンシャルスタッフィング対策不明",
                        severity="中",
                        evidence="CAPTCHA等の対策要素が不明",
                        reproduction_steps=[f"GET {url}", "ログイン/登録画面の対策要素を確認"],
                        category="J 認証",
                        test_type="受動的",
                        explanation="短時間の多数試行を抑制する仕組み（CAPTCHA等）が見当たりません。",
                        remediation="レート制限/アカウントロック/CAPTCHA/パスワード漏えい監視等の多層防御を導入してください。"
                    )
                )
        except Exception:
            pass
    # ログアウトがGETで成立する可能性
    if any(k in lower_url for k in ["/logout", "logout.php", "signout"]):
        if resp.request is not None and resp.request.method.upper() == "GET":
            findings.append(
                VulnerabilityFinding(
                    name="GETメソッドによるログアウトCSRFの可能性",
                    severity="低",
                    evidence="GETでログアウトエンドポイントに到達",
                    reproduction_steps=[f"IMGタグ等で {url} を読み込む"],
                    category="C CSRF",
                    test_type="受動的",
            )
        )
    # セッションIDがURLに露出（jsessionid, phpsessid など）
    try:
        if resp.status_code == 200:
            body = resp.text.lower()
            if any(tok in body for tok in ["jsessionid=", "phpsessid="]):
                findings.append(
                    VulnerabilityFinding(
                        name="セッションIDの漏えい（URL）",
                        severity="高",
                        evidence="URL内にセッション識別子らしき文字列",
                        reproduction_steps=[f"GET {url}", "HTML内のリンクに jsessionid 等を確認"],
                        category="K セッション/認証",
                        test_type="受動的",
                    )
                )
    except Exception:
        pass
    # HTMLコメント内の不要情報
    try:
        if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
            soup4 = BeautifulSoup(resp.text, "lxml")
            comments = soup4.find_all(string=lambda t: isinstance(t, str) and "<!--" in t)
            blob = "\n".join(map(str, comments)).lower()
            if any(k in blob for k in ["todo", "password", "apikey", "secret", "key="]):
                findings.append(
                    VulnerabilityFinding(
                        name="不要な情報の出力（HTMLコメント）",
                        severity="低",
                        evidence="コメントに機微な語を検出",
                        reproduction_steps=[f"GET {url}", "HTMLコメントを確認"],
                        category="出力",
                        test_type="受動的",
                    )
                )
    except Exception:
        pass
    # 例外/スタックトレースの露出
    try:
        if resp.status_code >= 500 or any(sig in resp.text.lower() for sig in ERROR_SIGNS):
            findings.append(
                VulnerabilityFinding(
                    name="不要なエラーメッセージの出力",
                    severity="中",
                    evidence=f"HTTP {resp.status_code}",
                    reproduction_steps=[f"GET {url}", "応答本文に例外/スタックトレースの露出"],
                    category="出力",
                    test_type="受動的",
                )
            )
    except Exception:
        pass
    # ローカルIPの露出
    try:
        import re
        if resp.status_code == 200:
            b = resp.text
            if re.search(r"(?:127\.0\.0\.1|10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3})\.(?:\d{1,3}))", b):
                findings.append(
                    VulnerabilityFinding(
                        name="ローカルIPアドレスの出力",
                        severity="低",
                        evidence="本文にプライベートIPらしき値",
                        reproduction_steps=[f"GET {url}", "本文内のIPアドレスを確認"],
                        category="Webサーバ/フレームワーク",
                        test_type="受動的",
                    )
                )
    except Exception:
        pass
    return findings


def _active_checks(url: str, client: httpx.Client, mode: ScanMode, options: ScanOptions | None) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    # HTTPS適用の有無/適用漏れ（通信）
    try:
        from urllib.parse import urlparse, urlunparse
        pr = urlparse(url)
        if pr.scheme == "http":
            https_url = urlunparse(("https", pr.netloc, pr.path, pr.params, pr.query, pr.fragment))
            try:
                r_https = client.get(https_url, timeout=6.0)
                r_http = client.get(url, timeout=6.0, follow_redirects=False)
                if r_http.status_code < 400 and (r_http.headers.get("location") is None):
                    findings.append(
                        VulnerabilityFinding(
                            name="HTTPSの未使用/適用漏れ",
                            severity="高",
                            evidence=f"HTTPアクセスが可能: {url}",
                            reproduction_steps=[f"GET {url}", f"GET {https_url}"],
                            category="通信",
                            test_type="能動的",
                            remediation="HTTPへのアクセスをHTTPSへリダイレクトし、HSTSを有効化してください。",
                        )
                    )
            except Exception:
                findings.append(
                    VulnerabilityFinding(
                        name="HTTPS未対応の可能性",
                        severity="中",
                        evidence=f"HTTPSに接続不可: {https_url}",
                        reproduction_steps=[f"GET {https_url}", "接続失敗を確認"],
                        category="通信",
                        test_type="能動的",
                    )
                )
    except Exception:
        pass
    # XSS tests (reflected)
    if options and options.xss.enabled and mode in (ScanMode.NORMAL, ScanMode.ATTACK):
        try:
            params = {options.xss.param_name: options.xss.payload}
            rr = client.get(url, params=params)
            if rr.status_code < 400:
                body_lower = rr.text.lower()
                ok = False
                for tok in options.xss.success_tokens:
                    if options.xss.match_mode == "contains" and tok.lower() in body_lower:
                        ok = True
                        break
                    # regex mode omitted for safety by default
                if ok:
                    findings.append(
                        VulnerabilityFinding(
                            name="潜在的な反射型XSS",
                            severity="高" if mode == ScanMode.ATTACK else "中",
                            evidence=f"トークン検出: {','.join(options.xss.success_tokens)}",
                            reproduction_steps=[
                                f"GET {url}?{options.xss.param_name}={options.xss.payload}",
                                "レスポンスにトークンが含まれることを確認",
                            ],
                            notes="会社ポリシーに応じた成功判定を options で調整可能",
                            category="B XSS",
                            test_type="能動的",
                        )
                    )
        except Exception:
            pass

    # SQL Injection tests（エラーベース + ブール/時間差を強化）
    if options and options.sqli.enabled and mode == ScanMode.ATTACK:
        try:
            p = options.sqli.param_name
            base_val = options.sqli.baseline_value
            inj_val = options.sqli.injection_template
            r_base = client.get(url, params={p: base_val})
            r_inj = client.get(url, params={p: inj_val})
            if r_inj.status_code < 400:
                # Compare length heuristic or error signatures
                diff = abs(len(r_inj.text) - len(r_base.text))
                large_change = len(r_base.text) > 0 and diff / max(1, len(r_base.text)) > 0.2
                more_errors = [
                    "syntax error", "warning: mysql", "unclosed quotation", "you have an error in your sql",
                    "fatal error", "sqlstate", "odbc", "ora-", "postgres", "sqlite", "mysql", "mariadb"
                ]
                error_sig = any(s in r_inj.text.lower() for s in (s.lower() for s in (options.sqli.error_signatures + more_errors)))
                if large_change or error_sig:
                    findings.append(
                        VulnerabilityFinding(
                            name="SQLインジェクションの可能性",
                            severity="高" if error_sig else "中",
                            evidence="応答長の大幅変化またはエラーメッセージ",
                            reproduction_steps=[
                                f"GET {url}?{p}={base_val}",
                                f"GET {url}?{p}={inj_val}",
                                "応答差異を比較",
                            ],
                            notes="注入テンプレートは options で変更可（安全な値に制限可能）",
                            category="A SQLi",
                            test_type="能動的",
                        )
                    )
        except Exception:
            pass
        # Boolean-based（true/falseの差分）
        try:
            p = options.sqli.param_name
            tval = f"{options.sqli.baseline_value} AND 1=1"
            fval = f"{options.sqli.baseline_value} AND 1=2"
            rt = client.get(url, params={p: tval})
            rf = client.get(url, params={p: fval})
            if rt.status_code < 400 and rf.status_code < 400:
                if abs(len(rt.text) - len(rf.text)) / max(1, len(rt.text)) > 0.15:
                    findings.append(
                        VulnerabilityFinding(
                            name="SQLインジェクションの可能性（ブール差）",
                            severity="中",
                            evidence="true/false 条件で応答差異",
                            reproduction_steps=[f"GET {url}?{p}={tval}", f"GET {url}?{p}={fval}", "差分を比較"],
                            category="A SQLi",
                            test_type="能動的",
                        )
                    )
        except Exception:
            pass
        # Boolean-based（true/falseの差分）
        try:
            p = options.sqli.param_name
            tval = f"{options.sqli.baseline_value} AND 1=1"
            fval = f"{options.sqli.baseline_value} AND 1=2"
            rt = client.get(url, params={p: tval})
            rf = client.get(url, params={p: fval})
            if rt.status_code < 400 and rf.status_code < 400:
                if abs(len(rt.text) - len(rf.text)) / max(1, len(rt.text)) > 0.15:
                    findings.append(
                        VulnerabilityFinding(
                            name="SQLインジェクションの可能性（ブール差）",
                            severity="中",
                            evidence="true/false 条件で応答差異",
                            reproduction_steps=[f"GET {url}?{p}={tval}", f"GET {url}?{p}={fval}", "差分を比較"],
                            category="A SQLi",
                            test_type="能動的",
                        )
                    )
        except Exception:
            pass
        # Time-based SQLi (遅延応答の検知)
        try:
            import time
            p = options.sqli.param_name
            time_payloads = [
                "1' AND SLEEP(5)-- ",
                "1 AND SLEEP(5)-- ",
                "1) AND SLEEP(5)-- ",
                "1 OR pg_sleep(5)--",
                "1; SELECT pg_sleep(5)--",
                "1' WAITFOR DELAY '0:0:5'--",
            ]
            for pay in time_payloads:
                t0 = time.perf_counter();
                rr = client.get(url, params={p: pay});
                dt = time.perf_counter() - t0
                if rr.status_code < 500 and dt > 4.0:
                    findings.append(
                        VulnerabilityFinding(
                            name="SQLインジェクションの可能性（時間差）",
                            severity="高",
                            evidence=f"タイムディレイ応答 {dt:.2f}s",
                            reproduction_steps=[f"GET {url}?{p}={pay}", "応答遅延を確認"],
                            category="A SQLi",
                            test_type="能動的",
                        )
                    )
                    break
        except Exception:
            pass
    # Open Redirect（検査強化: パラメータ拡張 + meta/JSの検出）
    if mode in (ScanMode.NORMAL, ScanMode.ATTACK):
        redirect_params = (
            "next", "redirect", "url", "return", "to", "dest", "destination",
            "redir", "returnTo", "continue", "forward", "goto", "target", "r", "u"
        )
        for pname in redirect_params:
            try:
                target = "https://example.com/"
                rr = client.get(url, params={pname: target}, follow_redirects=False)
                loc = rr.headers.get("location")
                if rr.status_code in (301, 302, 303, 307, 308) and loc and "example.com" in loc:
                    findings.append(
                        VulnerabilityFinding(
                            name="意図しないリダイレクト（Open Redirect）",
                            severity="中",
                            evidence=f"Location: {loc}",
                            reproduction_steps=[f"GET {url}?{pname}={target}", "Locationヘッダを確認"],
                            category="H 意図しないリダイレクト",
                            test_type="能動的",
                        )
                    )
                    break
            except Exception:
                continue
        # Meta refresh / JS遷移の検出
        try:
            rr2 = client.get(url, follow_redirects=True)
            if rr2.status_code < 400 and "example.com" in rr2.text.lower():
                import re
                html = rr2.text.lower()
                if re.search(r"""http-equiv\s*=\s*"refresh"[^"]+url\s*=\s*https?://example\.com""", html) or \
                   re.search(r"""window\.location\s*=\s*['\"]https?://example\.com""", html):
                    findings.append(
                        VulnerabilityFinding(
                            name="意図しないリダイレクト（Open Redirect）",
                            severity="中",
                            evidence="Meta refresh/JSで外部へ遷移",
                            reproduction_steps=[f"GET {url}", "HTML内のrefresh/JS遷移を確認"],
                            category="H 意図しないリダイレクト",
                            test_type="能動的",
                        )
                    )
        except Exception:
            pass

    # Host Header Injection（リダイレクト/リンクのホスト汚染）
    try:
        rrh = client.get(url, headers={"Host": "evil.example.com"})
        text_lower = rrh.text.lower()
        loc = rrh.headers.get("location", "").lower()
        if ("evil.example.com" in text_lower) or ("evil.example.com" in loc):
            findings.append(
                VulnerabilityFinding(
                    name="Hostヘッダ依存の挙動の可能性",
                    severity="中",
                    evidence="応答/Locationに任意Hostが混入",
                    reproduction_steps=["Hostヘッダをevil.example.comに設定し取得", "応答内のリンク/Locationを確認"],
                    category="I HTTPヘッダ",
                    test_type="能動的",
                )
            )
    except Exception:
        pass

    # CORSのOrigin反映（反射許可）
    try:
        rco = client.get(url, headers={"Origin": "http://evil.example.com"})
        aco = rco.headers.get("access-control-allow-origin", "")
        acc = rco.headers.get("access-control-allow-credentials", "").lower()
        if aco == "http://evil.example.com" and acc == "true":
            findings.append(
                VulnerabilityFinding(
                    name="CORSの過剰許可（Origin反射）",
                    severity="中",
                    evidence="ACAO に要求Originがそのまま反映 + Credentials",
                    reproduction_steps=["Originヘッダを変更して取得", "ACAO/ACC を確認"],
                    category="サイトデザイン/クロスオリジン",
                    test_type="能動的",
                )
            )
    except Exception:
        pass

    # パラメータ改ざん（role/isAdmin 等）による越権の可能性
    try:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        pr = urlparse(url)
        base = client.get(url)
        if base.status_code < 500:
            qs = parse_qs(pr.query)
            candidates = ["role", "isAdmin", "admin", "priv", "level"]
            for p in candidates:
                qs2 = dict(qs)
                qs2[p] = ["1"]
                newq = urlencode({k: v[0] for k, v in qs2.items()})
                u2 = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, newq, pr.fragment))
                r2 = client.get(u2)
                if (base.status_code in (401, 403)) and (r2.status_code == 200):
                    findings.append(
                        VulnerabilityFinding(
                            name="不正なパラメータ操作による越権",
                            severity="高",
                            evidence=f"{p}=1 で 401/403→200",
                            reproduction_steps=[f"GET {url}", f"GET {u2}"],
                            category="認可",
                            test_type="能動的",
                        )
                    )
                    break
                # 大きな差分（保守的）
                if r2.status_code < 400 and abs(len(r2.text) - len(base.text)) / max(1, len(base.text)) > 0.3:
                    findings.append(
                        VulnerabilityFinding(
                            name="不正なパラメータ操作の可能性",
                            severity="中",
                            evidence=f"{p}=1 で応答差分大",
                            reproduction_steps=[f"GET {url}", f"GET {u2}"],
                            category="認可",
                            test_type="能動的",
                        )
                    )
                    break
    except Exception:
        pass

    # バッファオーバーフロー/入力長による異常（攻撃モードのみ）
    if mode == ScanMode.ATTACK:
        try:
            long_payload = "A" * 4000
            rlong = client.get(url, params={"q": long_payload})
            if rlong.status_code >= 500 or any(s in rlong.text.lower() for s in ["segmentation fault", "stack overflow", "buffer overflow"]):
                findings.append(
                    VulnerabilityFinding(
                        name="バッファオーバーフローの可能性",
                        severity="高",
                        evidence=f"HTTP {rlong.status_code} もしくは異常メッセージ",
                        reproduction_steps=[f"GET {url}?q=(長い文字列)", "サーバエラー/異常を確認"],
                        category="入力/その他インジェクション",
                        test_type="能動的",
                    )
                )
        except Exception:
            pass

    # HTTPヘッダインジェクション（CRLF）簡易検査（攻撃モード）
    if mode == ScanMode.ATTACK:
        crlf_params = ("filename", "name", "download", "disposition", "header", "addheader")
        for pname in crlf_params:
            try:
                inj = "test%0d%0aX-Injection-Test: injected"
                rcr = client.get(url, params={pname: inj}, follow_redirects=False)
                # ヘッダ分離が成立するとカスタムヘッダが混入する可能性
                if any(h.lower() == "x-injection-test" for h in rcr.headers.keys()):
                    findings.append(
                        VulnerabilityFinding(
                            name="HTTPヘッダインジェクションの可能性",
                            severity="高",
                            evidence="レスポンスヘッダに 'X-Injection-Test' を検出",
                            reproduction_steps=[f"GET {url}?{pname}={inj}", "レスポンスヘッダを確認"],
                            category="I HTTPヘッダ",
                            test_type="能動的",
                        )
                    )
                    break
            except Exception:
                continue

    # SSRFの可能性（URL系パラメータで外部コンテンツ反映を簡易検知）
    try:
        for pname in ("url", "image", "fetch", "proxy", "target", "uri", "link", "feed", "callback"):
            rrs = client.get(url, params={pname: "http://example.com"})
            if rrs.status_code < 400 and ("example domain" in rrs.text.lower()):
                findings.append(
                    VulnerabilityFinding(
                        name="SSRF/サーバ側フェッチの可能性",
                        severity="中",
                        evidence=f"{pname}=http://example.com で外部サイト断片を検出",
                        reproduction_steps=[f"GET {url}?{pname}=http://example.com", "応答にExample Domain等の文字列"],
                        category="N SSRF/サーバ側要求",
                        test_type="能動的",
                    )
                )
                break
    except Exception:
        pass

    # HTTPメソッド悪用（TRACE/XSTなど）
    try:
        rrt = client.request("TRACE", url)
        if rrt.status_code < 400 and ("TRACE" in rrt.text or rrt.text.strip()):
            findings.append(
                VulnerabilityFinding(
                    name="TRACEメソッド有効の可能性",
                    severity="低",
                    evidence="TRACE応答を取得",
                    reproduction_steps=["TRACE メソッドで同URLを取得"],
                    category="I HTTPヘッダ",
                    test_type="能動的",
                )
            )
    except Exception:
        pass

    # テンプレートインジェクションの可能性（非常に保守的な簡易検査）
    try:
        baseline = client.get(url)
        if baseline.status_code < 400:
            base_body = baseline.text
            candidates = ["q", "s", "search", "query", "name", "title", "message"]
            payloads = ["{{7*7}}", "${{7*7}}", "#{7*7}", "<%= 7*7 %>"]
            for p in candidates:
                hit = False
                for pay in payloads:
                    rti = client.get(url, params={p: pay})
                    if rti.status_code < 400:
                        body = rti.text
                        # 49 が新たに現れるなどの変化（非常に単純な指標）
                        if ("49" in body) and ("49" not in base_body):
                            hit = True
                            break
                if hit:
                    findings.append(
                        VulnerabilityFinding(
                            name="テンプレートインジェクションの可能性",
                            severity="中",
                            evidence="数式評価結果らしき差分（'49'）",
                            reproduction_steps=[f"GET {url}?{p}={{7*7}}", "応答に '49' が含まれることを確認"],
                            category="M テンプレートインジェクション/その他",
                            test_type="能動的",
                        )
                    )
                    break
    except Exception:
        pass

    # ディレクトリ・トラバーサル（攻撃モード・オプトイン）
    if mode == ScanMode.ATTACK and options and getattr(options, "traversal", None) and getattr(options.traversal, "enabled", False):
        linux_payloads = [
            "../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
        ]
        win_payloads = [
            "..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        ]
        payloads = linux_payloads + win_payloads
        param_candidates = ("path", "file", "page", "template", "include", "filename", "dir", "download")
        for pname in param_candidates:
            for payload in payloads:
                try:
                    rr = client.get(url, params={pname: payload})
                    body = rr.text.lower()
                    if rr.status_code < 400 and ("root:x:" in body or "for 16-bit app support" in body):
                        findings.append(
                            VulnerabilityFinding(
                                name="ディレクトリ・トラバーサル",
                                severity="高",
                                evidence=f"パラメータ {pname} によるファイル露出の兆候",
                                reproduction_steps=[f"GET {url}?{pname}={payload}", "既知ファイル内容の露出を確認"],
                                category="G パス名パラメータ未チェック/ディレクトリ・トラバーサル",
                                test_type="能動的",
                            )
                        )
                        raise StopIteration
                except StopIteration:
                    break
                except Exception:
                    continue

    return findings


def _collect_params_from_html(base_url: str, html: str) -> Tuple[List[str], List[Dict[str, str]]]:
    names: List[str] = []
    forms: List[Dict[str, str]] = []
    try:
        soup = BeautifulSoup(html, "lxml")
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            method = (form.get("method") or "get").lower()
            inputs = {}
            for i in form.find_all(["input", "textarea", "select"]):
                n = i.get("name") or i.get("id")
                if not n:
                    continue
                t = (i.get("type") or "text").lower()
                if t in ("submit", "button", "image"):
                    continue
                inputs[n] = i.get("value") or ""
                names.append(n)
            forms.append({
                "action": urljoin(base_url, action),
                "method": method,
                "inputs": inputs,
            })
    except Exception:
        pass
    return list(dict.fromkeys(names)), forms


def _xss_form_tests(url: str, html: str, client: httpx.Client, mode: ScanMode, options: ScanOptions) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    names, forms = _collect_params_from_html(url, html)
    # Candidate names (common fields) + discovered names
    candidates = list(dict.fromkeys([options.xss.param_name] + names + [
        "q", "s", "search", "query", "message", "comment", "name", "title" 
    ]))
    payload = options.xss.payload
    tokens = [t.lower() for t in options.xss.success_tokens]

    # GET-only in Normal; include POST in Attack
    for f in forms:
        method = f.get("method", "get")
        if method == "post" and mode != ScanMode.ATTACK:
            continue
        action = f.get("action", url)
        inputs = dict(f.get("inputs", {}))
        hit = False
        for n in list(inputs.keys()):
            if n in candidates:
                inputs[n] = payload
                hit = True
        if not hit and inputs:
            # put payload into first text-like field as fallback
            first_key = next(iter(inputs.keys()))
            inputs[first_key] = payload
        try:
            if method == "post":
                r = client.post(action, data=inputs)
            else:
                r = client.get(action, params=inputs)
        except Exception:
            continue
        if r.status_code < 400:
            body_lower = r.text.lower()
            if any(t in body_lower for t in tokens):
                findings.append(
                    VulnerabilityFinding(
                        name="潜在的な反射型XSS",
                        severity="高" if mode == ScanMode.ATTACK else "中",
                        evidence=f"フォーム送信後にトークン検出",
                        reproduction_steps=[
                            f"{method.upper()} {action}",
                            f"パラメータにペイロードを投入（{options.xss.param_name} 等）",
                            "レスポンスにトークンが含まれることを確認",
                        ],
                        category="B XSS",
                        test_type="能動的",
                    )
                )
                break
    return findings


def _sqli_form_tests(url: str, html: str, client: httpx.Client, mode: ScanMode, options: ScanOptions) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    if not options.sqli.enabled or mode != ScanMode.ATTACK:
        return findings
    names, forms = _collect_params_from_html(url, html)
    inj_val = options.sqli.injection_template
    base_val = options.sqli.baseline_value
    targets = [options.sqli.param_name] + names
    for f in forms:
        method = f.get("method", "get")
        action = f.get("action", url)
        inputs = dict(f.get("inputs", {}))
        if not inputs:
            continue
        base_inputs = inputs.copy()
        inj_inputs = inputs.copy()
        chosen = None
        for n in inputs.keys():
            if n in targets:
                inj_inputs[n] = inj_val
                base_inputs[n] = base_val
                chosen = n
                break
        if not chosen:
            continue
        try:
            if method == "post":
                r_base = client.post(action, data=base_inputs)
                r_inj = client.post(action, data=inj_inputs)
            else:
                r_base = client.get(action, params=base_inputs)
                r_inj = client.get(action, params=inj_inputs)
        except Exception:
            continue
        if r_inj.status_code < 400:
            diff = abs(len(r_inj.text) - len(r_base.text))
            large_change = len(r_base.text) > 0 and diff / max(1, len(r_base.text)) > 0.2
            error_sig = any(s in r_inj.text.lower() for s in (s.lower() for s in options.sqli.error_signatures))
            if large_change or error_sig:
                findings.append(
                    VulnerabilityFinding(
                        name="SQLインジェクションの可能性",
                        severity="高" if error_sig else "中",
                        evidence="応答差分またはエラーメッセージ",
                        reproduction_steps=[f"{method.upper()} {action}", f"{chosen} に {inj_val} を投入"],
                        category="A SQLi",
                        test_type="能動的",
                    )
                )
                break
    return findings


def _upload_form_tests(url: str, html: str, client: httpx.Client, mode: ScanMode, options: ScanOptions) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    if not options.upload.enabled or mode != ScanMode.ATTACK:
        return findings
    try:
        soup = BeautifulSoup(html, "lxml")
        for form in soup.find_all("form"):
            method = (form.get("method") or "post").lower()
            if method != "post":
                continue
            action = urljoin(url, form.get("action") or url)
            file_inputs = form.find_all("input", attrs={"type": "file"})
            if not file_inputs:
                continue
            # choose a file field
            finput = None
            for fi in file_inputs:
                name = fi.get("name") or fi.get("id")
                if name:
                    finput = name
                    break
            if not finput:
                continue
            # other inputs
            fields = {}
            for i in form.find_all("input"):
                n = i.get("name") or i.get("id")
                if not n or n == finput:
                    continue
                t = (i.get("type") or "text").lower()
                if t in ("hidden", "text", "email"):
                    fields[n] = i.get("value") or "test"
            # try safe sample uploads
            for fname, content, ctype in options.upload.samples:
                files = {finput: (fname, content.encode("latin1", "ignore"), ctype)}
                try:
                    r = client.post(action, data=fields, files=files)
                except Exception:
                    continue
                if r.status_code < 400:
                    findings.append(
                        VulnerabilityFinding(
                            name="ファイルアップロード受理の可能性",
                            severity="中",
                            evidence=f"{finput} に {fname} を送信し {r.status_code}",
                            reproduction_steps=[f"POST {action}", f"ファイルフィールド {finput} に {fname} を送信"],
                            category="アップロード",
                            test_type="能動的",
                        )
                    )
                    break
    except Exception:
        pass
    return findings


def _cmdi_tests(url: str, client: httpx.Client, mode: ScanMode, options: ScanOptions) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    if not options.cmdi.enabled or mode != ScanMode.ATTACK:
        return findings
    try:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        pr = urlparse(url)
        qs = parse_qs(pr.query)
        to_test = [p for p in options.cmdi.param_candidates if p in qs]
        for p in to_test:
            base_val = qs[p][0]
            for payload in options.cmdi.payloads:
                qs2 = dict(qs)
                qs2[p] = [payload]
                newq = urlencode({k: v[0] for k, v in qs2.items()})
                u2 = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, newq, pr.fragment))
                try:
                    import time
                    t0 = time.perf_counter(); r = client.get(u2); dt = time.perf_counter() - t0
                except Exception:
                    continue
                text = r.text.lower()
                if any(sig in text for sig in (s.lower() for s in options.cmdi.error_signatures)):
                    findings.append(
                        VulnerabilityFinding(
                            name="OSコマンドインジェクションの可能性",
                            severity="高",
                            evidence="シェルエラーの兆候",
                            reproduction_steps=[f"GET {u2}", "レスポンスにシェルエラーが含まれる"],
                            category="D OSコマンドインジェクション",
                            test_type="能動的",
                        )
                    )
                    return findings
                if dt > 4.0:
                    findings.append(
                        VulnerabilityFinding(
                            name="OSコマンドインジェクションの可能性（時間差）",
                            severity="高",
                            evidence=f"タイムディレイ応答 {dt:.2f}s",
                            reproduction_steps=[f"GET {u2}", "応答遅延を確認"],
                            category="D OSコマンドインジェクション",
                            test_type="能動的",
                        )
                    )
                    return findings
    except Exception:
        pass
    return findings


EXPOSURE_PROBES = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/config.php",
    "/config.php.bak",
    "/.DS_Store",
    "/server-status",
    "/server-info",
]


def _exposure_sweep(base_url: str, client: httpx.Client) -> Dict[str, List[VulnerabilityFinding]]:
    out: Dict[str, List[VulnerabilityFinding]] = {}
    for p in EXPOSURE_PROBES:
        u = urljoin(base_url, p)
        try:
            r = client.get(u)
        except Exception:
            continue
        if r.status_code < 400:
            f = _passive_checks(u, r)
            if f:
                out[u] = f
    return out


def scan_targets(
    progress: Callable[[object], None],
    urls: List[str],
    mode: ScanMode,
    auth: Optional[AuthConfig] = None,
    alt_auth: Optional[AuthConfig] = None,
    options: Optional[ScanOptions] = None,
) -> ScanResult:
    endpoints: List[str] = list(urls)
    vulns: Dict[str, List[VulnerabilityFinding]] = {u: [] for u in endpoints}
    cookies = httpx.Cookies()
    if auth and auth.login_url and auth.username and auth.password:
        cookies = try_login(lambda _: None, urls[0] if urls else "", auth)
    client = httpx.Client(follow_redirects=True, timeout=8.0, cookies=cookies)
    client_public = httpx.Client(follow_redirects=True, timeout=8.0)
    alt_cookies = httpx.Cookies()
    client_alt: Optional[httpx.Client] = None
    if alt_auth and alt_auth.login_url and alt_auth.username and alt_auth.password:
        try:
            alt_cookies = try_login(lambda _: None, urls[0] if urls else "", alt_auth)
            client_alt = httpx.Client(follow_redirects=True, timeout=8.0, cookies=alt_cookies)
        except Exception:
            client_alt = None
    settings = Settings.load()
    logic = LogicAnalyzer(settings.ollama_base_url, settings.ollama_model)
    # セッション固定化/未ローテーションの簡易確認
    pre_cookie = None
    if auth and auth.login_url:
        try:
            pre = client_public.get(auth.login_url)
            for k, v in pre.cookies.items():
                if any(s in k.lower() for s in ["sess", "phpsessid", "jsessionid"]):
                    pre_cookie = (k, v)
                    break
        except Exception:
            pass
    # セッションIDの未ローテーション（簡易）
    if pre_cookie is not None:
        k, v = pre_cookie
        try:
            post_v = client.cookies.get(k)
            if post_v and post_v == v:
                urlv = auth.login_url or ""
                # attach to first endpoint bucket
                dest = endpoints[0] if endpoints else urlv
                vulns[dest] = vulns.get(dest, [])
                vulns[dest].append(
                    VulnerabilityFinding(
                        name="セッションID未ローテーションの可能性",
                        severity="高",
                        evidence=f"ログイン前後で {k} が同一",
                        reproduction_steps=["ログイン前にCookieを取得", "ログイン後にCookieを比較"],
                        category="K セッション/認証",
                        test_type="能動的",
                        explanation="認証成功後にセッションIDが再生成されず、セッション固定化のリスクがあります。",
                        remediation="ログイン成功時にセッションIDを必ず再生成してください。"
                    )
                )
        except Exception:
            pass
    for i, url in enumerate(endpoints, start=1):
        try:
            r = client.get(url)
            vulns[url].extend(_passive_checks(url, r))
            vulns[url].extend(_active_checks(url, client, mode, options or ScanOptions()))
            vulns[url].extend(_cmdi_tests(url, client, mode, options or ScanOptions()))
            # フォームベースのXSS/SQLiテスト
            if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
                html = r.text
                vulns[url].extend(_xss_form_tests(url, html, client, mode, options or ScanOptions()))
                vulns[url].extend(_sqli_form_tests(url, html, client, mode, options or ScanOptions()))
                vulns[url].extend(_upload_form_tests(url, html, client, mode, options or ScanOptions()))
            # 危険なHTTPメソッド（OPTIONSのAllowで確認）
            try:
                ro = client.options(url)
                allow = ro.headers.get("allow", "")
                if any(m in allow for m in ["PUT", "DELETE", "PATCH", "PROPFIND", "MKCOL"]):
                    vulns[url].append(
                        VulnerabilityFinding(
                            name="危険なHTTPメソッド",
                            severity="中",
                            evidence=f"Allow: {allow}",
                            reproduction_steps=["OPTIONSでAllowヘッダを確認"],
                            category="I HTTPヘッダ",
                            test_type="能動的",
                        )
                    )
            except Exception:
                pass

            # 価格改変などのロジック検査（観測ベース、GETのみ）
            if options and options.business.enabled and r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
                html = r.text
                suggestions = logic.suggest_tests(html, max_suggestions=options.business.max_suggestions)
                for s in suggestions:
                    pname = s.get("param")
                    val = s.get("suggested_value", "1")
                    if not pname:
                        continue
                    try:
                        r2 = client.get(url, params={pname: val})
                    except Exception:
                        continue
                    if r2.status_code < 400:
                        # 単純比較: 金額らしき数字/通貨が変化したか
                        import re
                        pat = re.compile(r"([¥$]\s?\d+[\d,]*|\d+[\d,]*\s?(?:円|yen|usd))", re.IGNORECASE)
                        nums1 = set(pat.findall(html))
                        nums2 = set(pat.findall(r2.text))
                        if nums1 != nums2:
                            vulns[url].append(
                                VulnerabilityFinding(
                                    name="価格改変の可能性（ロジック）",
                                    severity="中",
                                    evidence=f"パラメータ {pname} を {val} にした際に表示金額が変化",
                                    reproduction_steps=[f"GET {url}?{pname}={val}", "価格表示の差分を確認"],
                                    category="ロジック",
                                    test_type="能動的",
                                    notes=s.get("reason", ""),
                                )
                            )
            # 認可制御の不備（簡易）: /admin 等が未認証でも同等に閲覧可能
            path_lower = urlparse(url).path.lower()
            if auth and any(k in path_lower for k in ["/admin", "/manage", "/dashboard"]):
                try:
                    r_pub = client_public.get(url)
                    if r_pub.status_code == 200 and r.status_code == 200 and len(r_pub.text) == len(r.text):
                        vulns[url].append(
                            VulnerabilityFinding(
                                name="認可制御の不備の可能性",
                                severity="高",
                                evidence="未認証と認証済みの応答が同等",
                                reproduction_steps=[
                                    f"未認証で GET {url}",
                                    f"認証後に GET {url}",
                                    "応答差異がないことを確認",
                                ],
                                category="L 認可制御の不備",
                                test_type="能動的",
                            )
                        )
                except Exception:
                    pass
            # 低権限で管理ページが閲覧できる可能性（比較アカウント）
            if client_alt is not None and any(k in path_lower for k in ["/admin", "/manage", "/dashboard"]):
                try:
                    r_low = r
                    r_high = client_alt.get(url)
                    if r_low.status_code == 200 and r_high.status_code == 200:
                        vulns[url].append(
                            VulnerabilityFinding(
                                name="低権限で管理ページ閲覧の可能性",
                                severity="高",
                                evidence="一般アカウントでも200で閲覧可能",
                                reproduction_steps=["一般と管理アカウントで同URLを取得し差異を確認"],
                                category="L 認可制御の不備",
                                test_type="能動的",
                            )
                        )
                except Exception:
                    pass
            # LLM所見（受動的）: HTMLから潜在的な問題の候補を抽出
            try:
                if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
                    html = r.text
                    notes = logic.assess_vulnerabilities(html, url, max_items=3)
                    for it in notes:
                        vulns[url].append(
                            VulnerabilityFinding(
                                name=it.get("name", "LLM所見"),
                                severity=it.get("severity", "中"),
                                evidence=it.get("reason", ""),
                                reproduction_steps=["HTMLレビュー/静的所見（AI）"],
                                category=it.get("category", "LLM所見"),
                                test_type="受動的",
                            )
                        )
            except Exception:
                pass
            # IDORの可能性（GETの数値idパラメータ）
            try:
                parsed = urlparse(url)
                if parsed.query and "id=" in parsed.query:
                    from urllib.parse import parse_qs, urlencode
                    qs = parse_qs(parsed.query)
                    if "id" in qs:
                        cur = qs["id"][0]
                        if cur.isdigit():
                            test_id = str(int(cur) + 1)
                            qs2 = dict(qs)
                            qs2["id"] = [test_id]
                            newq = urlencode({k: v[0] for k, v in qs2.items()})
                            u2 = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{newq}"
                            r_id = client.get(u2)
                            if r_id.status_code == 200 and len(r_id.text) != len(r.text):
                                vulns[url].append(
                                    VulnerabilityFinding(
                                        name="IDORの可能性（直接オブジェクト参照）",
                                        severity="高",
                                        evidence=f"id={cur} と id={test_id} で応答に有意な差",
                                        reproduction_steps=[f"GET {url}", f"GET {u2}", "差分を比較"],
                                        category="L 認可制御の不備",
                                        test_type="能動的",
                                    )
                                )
            except Exception:
                pass
        except Exception as e:
            vulns[url].append(
                VulnerabilityFinding(
                    name="リクエストエラー",
                    severity="情報",
                    evidence=str(e),
                    reproduction_steps=[f"GET {url}", "ネットワークエラー発生"],
                    category="その他",
                    test_type="受動的",
                )
            )
        progress(f"スキャン中… {i}/{len(endpoints)}")
    client.close()
    client_public.close()
    if client_alt is not None:
        client_alt.close()
    # 集約所見: 認可処理の有無/適用範囲、HTTPS適用範囲
    try:
        has_authz = any(
            any((v.severity in ("高", "中", "低", "情報")) and (v.category or "").startswith("L ") or (v.name and "認可" in v.name)
                for v in vulns.get(u, []))
            for u in endpoints
        )
        # 401/403の存在で簡易判定
        # ここではリクエスト結果のステータスを追っていないため、既存所見から推測に留める
        summary_endpoint = endpoints[0] if endpoints else ""
        if summary_endpoint:
            vulns[summary_endpoint] = vulns.get(summary_endpoint, [])
            vulns[summary_endpoint].append(
                VulnerabilityFinding(
                    name="認可処理の有無/認可方法（簡易）",
                    severity="情報",
                    explanation="検出所見から認可関連の兆候を集約。保護すべきURLに401/403/認可チェックが無い場合、適用漏れの可能性。",
                    category="認可",
                    test_type="受動的",
                )
            )
            # HTTPS適用範囲（http/https の混在有無）
            http_count = sum(1 for u in endpoints if u.startswith("http://"))
            https_count = sum(1 for u in endpoints if u.startswith("https://"))
            vulns[summary_endpoint].append(
                VulnerabilityFinding(
                    name="HTTPSの適用範囲（簡易）",
                    severity="情報",
                    explanation=f"HTTPS: {https_count} / HTTP: {http_count}",
                    category="通信",
                    test_type="受動的",
                )
            )
    except Exception:
        pass
    # Additional exposure sweep on site root
    if endpoints:
        origin = endpoints[0]
        o = urlparse(origin)
        base_origin = f"{o.scheme}://{o.netloc}/"
        client2 = httpx.Client(follow_redirects=True, timeout=8.0, cookies=cookies)
        extra = _exposure_sweep(base_origin, client2)
        client2.close()
        for u, fs in extra.items():
            if u not in vulns:
                vulns[u] = []
                endpoints.append(u)
            vulns[u].extend(fs)
    # Use the origin of first URL as target label
    target = endpoints[0] if endpoints else ""
    return ScanResult(target=target, mode=mode, endpoints=endpoints, vulns_by_endpoint=vulns)


def scan_targets_worker(urls: List[str], mode: ScanMode, auth: Optional[AuthConfig] = None, alt_auth: Optional[AuthConfig] = None, options: Optional[ScanOptions] = None) -> FunctionWorker[ScanResult]:
    return FunctionWorker(scan_targets, urls, mode, auth, alt_auth, options)
