from __future__ import annotations

from typing import List, Set, Callable, Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup, Comment
import re

from mbsd_tool.core.utils import FunctionWorker
from mbsd_tool.core.models import AuthConfig
from mbsd_tool.core.auth import try_login


DEFAULT_WORDLIST = [
    "admin",
    "login",
    "logout",
    "user",
    "users",
    "api",
    "auth",
    "dashboard",
    "pass",
    "pass/example",
    "config",
    "debug",
    "status",
    "health",
    ".git",
    ".env",
    "backup",
    "old",
]

# Additional sensitive/admin candidates and common exposures
ADMIN_CANDIDATES = [
    "admin/login",
    "admin/dashboard",
    "administrator",
    "manage",
    "management",
    "moderator",
    "staff",
    "console",
    "wp-admin",
    "wp-login.php",
    "phpmyadmin",
    "pma",
    "adminer.php",
    "adminer",
    "setup",
    "install",
    "_debugbar",
    "rails/info/routes",
    "actuator",
    "actuator/health",
    "actuator/metrics",
    "actuator/env",
    "grafana",
    "kibana",
    "prometheus",
]

EXPOSED_FILES = [
    ".git/HEAD",
    ".git/config",
    ".gitignore",
    ".svn/entries",
    ".hg/dirstate",
    ".DS_Store",
    ".htaccess",
    ".htpasswd",
    "web.config",
    "config.php",
    "wp-config.php",
    "composer.json",
    "composer.lock",
    "package.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile",
    "Gemfile.lock",
    "requirements.txt",
    "local_settings.py",
    "settings.py",
    "database.yml",
    "appsettings.json",
    "docker-compose.yml",
    "Dockerfile",
    "backup.sql",
    "dump.sql",
    "db.sql",
    "error.log",
    "access.log",
]

BACKUP_SUFFIXES = [
    "~",
    ".bak",
    ".old",
    ".orig",
    ".backup",
    ".save",
    ".bkp",
    ".tmp",
    ".zip",
    ".tar.gz",
    ".swp",
]


def _same_origin(url: str, base: str) -> bool:
    u = urlparse(url)
    b = urlparse(base)
    return u.scheme == b.scheme and u.netloc == b.netloc


def _gather_links_and_hidden(base: str, html: str) -> List[str]:
    out: List[str] = []
    soup = BeautifulSoup(html, "lxml")
    # anchor links
    for a in soup.find_all("a"):
        href = a.get("href")
        if href:
            out.append(urljoin(base, href))
    # forms actions
    for form in soup.find_all("form"):
        action = form.get("action")
        if action:
            out.append(urljoin(base, action))
    # HTML comments
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for c in comments:
        out.extend(_extract_url_like(base, str(c)))
    # inline scripts
    for s in soup.find_all("script"):
        if s.string:
            out.extend(_extract_url_like(base, s.string))
    return out


URL_RELS = re.compile(r"(?:(?:https?://[^\s'\"]+)|(?:/[^\s'\"<>]+))")


def _extract_url_like(base: str, text: str) -> List[str]:
    found: List[str] = []
    for m in URL_RELS.findall(text or ""):
        url = m
        if not (url.startswith("http://") or url.startswith("https://")):
            url = urljoin(base, url)
        if _same_origin(url, base):
            found.append(url)
    return found


def _fetch_robots_candidates(base: str, client: httpx.Client) -> List[str]:
    urls: List[str] = []
    try:
        r = client.get(urljoin(base, "robots.txt"))
        if r.status_code < 400:
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        urls.append(urljoin(base, path))
    except Exception:
        pass
    return urls


def _fetch_sitemap_candidates(base: str, client: httpx.Client) -> List[str]:
    urls: List[str] = []
    try:
        r = client.get(urljoin(base, "sitemap.xml"))
        if r.status_code < 400 and r.headers.get("content-type", "").lower().find("xml") != -1:
            soup = BeautifulSoup(r.text, "xml")
            for loc in soup.find_all("loc"):
                u = loc.get_text().strip()
                if u:
                    urls.append(u)
    except Exception:
        pass
    return urls


def enumerate_paths(
    progress: Callable[[object], None],
    base_url: str,
    auth: Optional[AuthConfig] = None,
    timeout: float = 6.0,
    max_pages: int = 200,
    max_depth: int = 2,
) -> List[str]:
    base = base_url if base_url.endswith("/") else base_url + "/"
    discovered: Set[str] = set()
    cookies = httpx.Cookies()
    if auth and auth.login_url and auth.username and auth.password:
        # Try login to obtain cookies
        cookies = try_login(lambda _: None, base, auth)
    # Prepare both public and authenticated clients (union of results)
    client_public = httpx.Client(follow_redirects=True, timeout=timeout)
    client_auth = httpx.Client(follow_redirects=True, timeout=timeout, cookies=cookies)

    def _first_ok(url: str) -> bool:
        for c in (client_auth, client_public):
            try:
                r = c.get(url)
                if r.status_code < 400:
                    return True
            except Exception:
                continue
        return False

    # 1) Dictionary enumeration (non-destructive GET)
    for word in DEFAULT_WORDLIST + ADMIN_CANDIDATES + EXPOSED_FILES:
        url = urljoin(base, word)
        if _first_ok(url):
            discovered.add(url)
            progress(len(discovered))

    # 1.5) robots.txt & sitemap.xml hints
    for hint in _fetch_robots_candidates(base, client_auth) + _fetch_sitemap_candidates(base, client_auth):
        try:
            if _first_ok(hint) and _same_origin(hint, base):
                discovered.add(hint)
                progress(len(discovered))
        except Exception:
            pass

    # 2) BFS crawl (depth-limited)
    try:
        frontier = [(base, 0, 'auth'), (base, 0, 'public')]
        visited_auth: Set[str] = set()
        visited_public: Set[str] = set()
        while frontier and (len(visited_auth) + len(visited_public)) < max_pages:
            url, depth, tag = frontier.pop(0)
            visited = visited_auth if tag == 'auth' else visited_public
            client = client_auth if tag == 'auth' else client_public
            if url in visited:
                continue
            visited.add(url)
            try:
                r = client.get(url)
            except Exception:
                continue
            if r.status_code >= 400:
                continue
            discovered.add(url)
            progress(len(discovered))
            if depth >= max_depth:
                continue
            ct = r.headers.get("content-type", "")
            if "text/html" not in ct:
                continue
            for link in _gather_links_and_hidden(url, r.text):
                if _same_origin(link, base) and link not in visited:
                    frontier.append((link, depth + 1, tag))
    finally:
        client_public.close()
        client_auth.close()

    # 3) Backup variants for common files
    client2_pub = httpx.Client(follow_redirects=True, timeout=timeout)
    client2_auth = httpx.Client(follow_redirects=True, timeout=timeout, cookies=cookies)
    def _try_add(u: str) -> None:
        nonlocal discovered
        try:
            ok = False
            for c in (client2_auth, client2_pub):
                try:
                    rc = c.get(u)
                    if rc.status_code < 400:
                        ok = True
                        break
                except Exception:
                    continue
            if ok and _same_origin(u, base):
                if u not in discovered:
                    discovered.add(u)
                    progress(len(discovered))
        except Exception:
            pass

    INDEX_FILES = [
        "index.php",
        "index.html",
        "index.asp",
        "index.aspx",
        "login.php",
        "config.php",
        "wp-config.php",
        "web.config",
    ]
    for name in INDEX_FILES:
        for suf in BACKUP_SUFFIXES:
            _try_add(urljoin(base, name + suf))

    # Also try backup variants for discovered files
    for u in list(discovered):
        path = urlparse(u).path
        if path and "." in path.rsplit("/", 1)[-1] and not path.endswith("/"):
            for suf in BACKUP_SUFFIXES:
                _try_add(urljoin(base, path + suf))

    client2_pub.close()
    client2_auth.close()
    return sorted(discovered)


def enumerate_paths_worker(base_url: str, auth: Optional[AuthConfig] = None) -> FunctionWorker[List[str]]:
    return FunctionWorker(enumerate_paths, base_url, auth)
