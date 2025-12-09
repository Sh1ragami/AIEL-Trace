from __future__ import annotations

from typing import Any, Dict, List
import json

import httpx


PROMPT = (
    "You receive an HTML page. Identify potential business-logic risks, especially price manipulation. "
    "Output JSON with an array 'tests'. Each test has: { 'param': string, 'suggested_value': string, 'reason': string }. "
    "Prefer GET parameters that look like price/amount/qty/total. Limit to 3 suggestions."
)


class LogicAnalyzer:
    def __init__(self, base_url: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    def suggest_tests(self, html: str, max_suggestions: int = 3) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": html[:20000]},
            ],
            "stream": False,
        }
        try:
            r = httpx.post(url, json=payload, timeout=15.0)
            r.raise_for_status()
            data = r.json()
            content = data.get("message", {}).get("content", "")
            obj = json.loads(content)
            tests = obj.get("tests", []) if isinstance(obj, dict) else []
            out: List[Dict[str, Any]] = []
            for t in tests:
                if not isinstance(t, dict):
                    continue
                param = str(t.get("param", "")).strip()
                val = str(t.get("suggested_value", "1")).strip()
                reason = str(t.get("reason", "")).strip()
                if not param:
                    continue
                out.append({"param": param, "suggested_value": val, "reason": reason})
                if len(out) >= max_suggestions:
                    break
            return out
        except Exception:
            # Fallback heuristic when LLM unavailable
            return [
                {"param": "price", "suggested_value": "1", "reason": "価格らしきパラメータを下げる"},
                {"param": "amount", "suggested_value": "1", "reason": "数量/金額の縮小"},
            ][:max_suggestions]

    def assess_vulnerabilities(self, html: str, url: str, max_items: int = 5) -> List[Dict[str, Any]]:
        """LLMにHTMLを渡し、潜在的な脆弱性所見をJSONで取得する（ロバストなフォールバック付き）。"""
        prompt = (
            "You are a security tester. Given an HTML page and its URL, list potential web vulnerabilities that might be present. "
            "Respond as compact JSON: {\"findings\":[{\"name\":str,\"severity\":str,\"reason\":str,\"category\":str}...]}. "
            "Use Japanese for names and reasons when possible (e.g., XSS, CSRF, 認可不備). Limit to %d items. " % max_items
        )
        url_api = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"URL: {url}\nHTML:\n" + html[:20000]},
            ],
            "stream": False,
        }
        try:
            r = httpx.post(url_api, json=payload, timeout=15.0)
            r.raise_for_status()
            data = r.json()
            content = data.get("message", {}).get("content", "{}")
            obj = json.loads(content)
            arr = obj.get("findings", []) if isinstance(obj, dict) else []
            out: List[Dict[str, Any]] = []
            for it in arr:
                if not isinstance(it, dict):
                    continue
                name = str(it.get("name", "潜在的な問題")).strip() or "潜在的な問題"
                sev = str(it.get("severity", "中")).strip() or "中"
                reason = str(it.get("reason", "")).strip()
                cat = str(it.get("category", "LLM所見")).strip() or "LLM所見"
                out.append({"name": name, "severity": sev, "reason": reason, "category": cat})
                if len(out) >= max_items:
                    break
            return out
        except Exception:
            # Fallback簡易所見
            return [
                {"name": "CSRF対策不明", "severity": "中", "reason": "POSTフォームにCSRFトークンが見当たらない可能性", "category": "C CSRF"},
                {"name": "クリックジャッキングの可能性", "severity": "低", "reason": "X-Frame-Options/CSPのframe-ancestors不備", "category": "その他"},
            ][:max_items]
