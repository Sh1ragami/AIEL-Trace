from __future__ import annotations

from typing import Callable, Dict, List, Optional

import httpx

from mbsd_tool.core.models import ScanMode, VulnerabilityFinding, ScanResult, AuthConfig
from mbsd_tool.core.utils import FunctionWorker
from mbsd_tool.core.auth import try_login
from urllib.parse import urlparse, urljoin


SEC_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]


def _passive_checks(url: str, resp: httpx.Response) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    # Missing security headers
    missing = [h for h in SEC_HEADERS if h not in resp.headers]
    if missing:
        findings.append(
            VulnerabilityFinding(
                name="Missing Security Headers",
                severity="Medium",
                evidence=", ".join(missing),
                reproduction_steps=[f"GET {url}", "Review response headers"],
            )
        )
    # Directory listing heuristic
    ct = resp.headers.get("content-type", "")
    if resp.status_code == 200 and "text/html" in ct and "Index of /" in resp.text:
        findings.append(
            VulnerabilityFinding(
                name="Directory Listing Enabled",
                severity="Medium",
                evidence="Page title contains 'Index of /'",
                reproduction_steps=[f"GET {url}", "Observe index listing"],
            )
        )
    # Technology disclosure
    powered = resp.headers.get("x-powered-by") or resp.headers.get("server")
    if powered:
        findings.append(
            VulnerabilityFinding(
                name="Technology Disclosure",
                severity="Low",
                evidence=f"Header: {powered}",
                reproduction_steps=[f"GET {url}", "Review headers 'Server'/'X-Powered-By'"],
            )
        )
    # Sensitive file exposures
    lower_url = url.lower()
    if "/.git/" in lower_url:
        findings.append(
            VulnerabilityFinding(
                name="Gitリポジトリの露出",
                severity="High",
                evidence=f"{url}",
                reproduction_steps=[f"GET {url}", "機密情報（リビジョン/設定）取得可能"],
            )
        )
    if lower_url.endswith("/.env"):
        if any(k in resp.text for k in ["APP_KEY", "DB_PASSWORD", "DATABASE_URL", "SECRET_KEY"]):
            findings.append(
                VulnerabilityFinding(
                    name="環境変数ファイルの露出 (.env)",
                    severity="High",
                    evidence="機密キー/DB情報を含む可能性",
                    reproduction_steps=[f"GET {url}", "内容を確認"],
                )
            )
    if lower_url.endswith(".sql") or any(s in resp.text for s in ["CREATE TABLE", "INSERT INTO", "DROP TABLE"]):
        findings.append(
            VulnerabilityFinding(
                name="DBダンプの露出",
                severity="High",
                evidence="SQLスキーマやデータが含まれる",
                reproduction_steps=[f"GET {url}", "レスポンスを確認"],
            )
        )
    if lower_url.endswith(".map") or "sourceMappingURL" in resp.text:
        findings.append(
            VulnerabilityFinding(
                name="ソースマップの露出",
                severity="Low",
                evidence=".mapによりソース構造が開示",
                reproduction_steps=[f"GET {url}", ".mapの内容を確認"],
            )
        )
    for suf in ["~", ".bak", ".old", ".orig", ".backup", ".save", ".bkp", ".tmp", ".zip", ".tar.gz", ".swp"]:
        if lower_url.endswith(suf):
            findings.append(
                VulnerabilityFinding(
                    name="バックアップ/一時ファイルの露出",
                    severity="Medium",
                    evidence=f"サフィックス: {suf}",
                    reproduction_steps=[f"GET {url}", "不要ファイルの公開を確認"],
                )
            )
    return findings


def _active_checks(url: str, client: httpx.Client, mode: ScanMode) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    # Minimal, non-destructive probes: reflected string test for XSS pattern echo
    if mode in (ScanMode.NORMAL, ScanMode.ATTACK):
        try:
            probe = "mbsd_probe_12345"
            params = {"q": probe}
            rr = client.get(url, params=params)
            if rr.status_code < 400 and probe in rr.text:
                findings.append(
                    VulnerabilityFinding(
                        name="Potential Reflected Input",
                        severity="Info",
                        evidence="Echo of marker in response",
                        reproduction_steps=[f"GET {url}?q={probe}", "Response contains marker"],
                    )
                )
        except Exception:
            pass
    # Attack mode placeholder: more intrusive tests would go here
    if mode == ScanMode.ATTACK:
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
) -> ScanResult:
    endpoints: List[str] = list(urls)
    vulns: Dict[str, List[VulnerabilityFinding]] = {u: [] for u in endpoints}
    cookies = httpx.Cookies()
    if auth and auth.login_url and auth.username and auth.password:
        cookies = try_login(lambda _: None, urls[0] if urls else "", auth)
    client = httpx.Client(follow_redirects=True, timeout=8.0, cookies=cookies)
    for i, url in enumerate(endpoints, start=1):
        try:
            r = client.get(url)
            vulns[url].extend(_passive_checks(url, r))
            vulns[url].extend(_active_checks(url, client, mode))
        except Exception as e:
            vulns[url].append(
                VulnerabilityFinding(
                    name="Request Error",
                    severity="Info",
                    evidence=str(e),
                    reproduction_steps=[f"GET {url}", "Network error raised"],
                )
            )
        progress(f"スキャン中… {i}/{len(endpoints)}")
    client.close()
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


def scan_targets_worker(urls: List[str], mode: ScanMode, auth: Optional[AuthConfig] = None) -> FunctionWorker[ScanResult]:
    return FunctionWorker(scan_targets, urls, mode, auth)
