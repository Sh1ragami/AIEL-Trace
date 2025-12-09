from __future__ import annotations

from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from mbsd_tool.core.models import AuthConfig
from mbsd_tool.core.utils import FunctionWorker


USERNAME_KEYS = [
    "username",
    "email",
    "user",
    "login",
    "userid",
    "user_id",
]


def _detect_login_form(html: str):
    soup = BeautifulSoup(html, "lxml")
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        pwd = next((i for i in inputs if i.get("type") == "password"), None)
        if not pwd:
            continue
        # username field
        uname = None
        for i in inputs:
            name = (i.get("name") or i.get("id") or "").lower()
            if name in USERNAME_KEYS or i.get("type") in ("text", "email"):
                uname = i
                break
        if not uname:
            uname = pwd  # fallback: single-field password? rare; we'll still proceed
        return form, uname, pwd
    return None, None, None


def _build_login_payload(form, uname_input, pwd_input, username: str, password: str):
    payload = {}
    for i in form.find_all("input"):
        name = i.get("name") or i.get("id")
        if not name:
            continue
        t = (i.get("type") or "").lower()
        if i is uname_input:
            payload[name] = username
        elif i is pwd_input:
            payload[name] = password
        elif t in ("hidden", "submit"):
            payload[name] = i.get("value") or ""
        else:
            # leave empty
            payload[name] = i.get("value") or ""
    return payload


def _looks_logged_in(html: str) -> bool:
    soup = BeautifulSoup(html, "lxml")
    text = soup.get_text(" ", strip=True).lower()
    return any(tok in text for tok in ["logout", "sign out", "ログアウト"]) and not any(
        tok in text for tok in ["login", "ログイン", "sign in"]
    )


def try_login(progress: Callable[[object], None], base_url: str, auth: AuthConfig) -> httpx.Cookies:
    cookies = httpx.Cookies()
    if not auth or not auth.login_url or not auth.username or not auth.password:
        progress("認証情報が不足しています")
        return cookies
    # Allow relative login URL
    parsed = urlparse(auth.login_url)
    login_url = auth.login_url if parsed.scheme else urljoin(base_url, auth.login_url)
    timeout = httpx.Timeout(connect=5.0, read=7.0, write=5.0, pool=5.0)
    client = httpx.Client(follow_redirects=True, timeout=timeout, cookies=cookies)
    try:
        progress("ログインページ取得中…")
        r1 = client.get(login_url)
        form, uname, pwd = _detect_login_form(r1.text)
        if not form or not pwd or not uname:
            # try direct POST fallback with common field names
            payload = {"username": auth.username, "password": auth.password}
            action = login_url
            method = "post"
        else:
            action = urljoin(login_url, form.get("action") or login_url)
            method = (form.get("method") or "post").lower()
            payload = _build_login_payload(form, uname, pwd, auth.username, auth.password)

        progress("ログイン送信中…")
        if method == "post":
            r2 = client.post(action, data=payload)
        else:
            r2 = client.get(action, params=payload)

        # verify by fetching base
        r3 = client.get(base_url)
        if _looks_logged_in(r2.text) or _looks_logged_in(r3.text) or any(
            k.lower().startswith("session") for k in client.cookies.keys()
        ):
            progress("ログイン成功")
        else:
            progress("ログイン不明（失敗の可能性）")
    except Exception as e:
        progress(f"ログインエラー: {e}")
    finally:
        client.close()
    # return the cookies captured in the client (not the initial empty jar)
    return client.cookies


def login_worker(base_url: str, auth: AuthConfig) -> FunctionWorker[httpx.Cookies]:
    return FunctionWorker(try_login, base_url, auth)
