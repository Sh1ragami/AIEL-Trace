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
    return findings


def _active_checks(url: str, client: httpx.Client, mode: ScanMode, options: ScanOptions | None) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
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
                            severity="中",
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

    # SQL Injection tests (very conservative)
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
                error_sig = any(s in r_inj.text.lower() for s in (s.lower() for s in options.sqli.error_signatures))
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
    # Open Redirect（安全な検査）
    if mode in (ScanMode.NORMAL, ScanMode.ATTACK):
        for pname in ("next", "redirect", "url", "return", "to"):
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

    # ディレクトリ・トラバーサル（攻撃モード・オプトイン）
    if mode == ScanMode.ATTACK and options and getattr(options, "traversal", None) and getattr(options.traversal, "enabled", False):
        payload = getattr(options.traversal, "payload", "../../../../../../etc/passwd")
        for pname in ("path", "file", "page"):
            try:
                rr = client.get(url, params={pname: payload})
                if rr.status_code < 400 and "root:x:0:" in rr.text:
                    findings.append(
                        VulnerabilityFinding(
                            name="ディレクトリ・トラバーサル",
                            severity="高",
                            evidence="/etc/passwd の一部を検出",
                            reproduction_steps=[f"GET {url}?{pname}={payload}", "レスポンスにpasswd内容が含まれる"],
                            category="G パス名パラメータ未チェック/ディレクトリ・トラバーサル",
                            test_type="能動的",
                        )
                    )
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
                        severity="中",
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
                    r = client.get(u2)
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
