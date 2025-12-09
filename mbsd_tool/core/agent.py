from __future__ import annotations

import json
from typing import Any, Dict

import httpx


SYSTEM_PROMPT = (
    "You are a web testing agent. You receive the current page HTML and must respond "
    "with a small next action as JSON. Prefer simple exploration: click main links, "
    "follow navigation, or move cursor to visible elements. Respond with one JSON object.\n\n"
    "Schema: {\n  'type': 'move_click' | 'navigate' | 'move_only',\n  'x': <int>, 'y': <int>,\n  'url': <string, when type='navigate'>\n}\n\n"
    "Pick reasonable viewport coordinates if click/move."
)


class AgentClient:
    def __init__(self, base_url: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    def _post_chat(self, messages: list[dict[str, str]]) -> str:
        # Ollama chat API
        url = f"{self.base_url}/api/chat"
        payload = {"model": self.model, "messages": messages, "stream": False}
        try:
            r = httpx.post(url, json=payload, timeout=15.0)
            r.raise_for_status()
            data = r.json()
            return data.get("message", {}).get("content", "")
        except Exception:
            # Fallback: minimal heuristic
            return json.dumps({"type": "move_only", "x": 140, "y": 220})

    def decide_next_action(self, html: str, auth: Any | None = None) -> Dict[str, Any]:
        auth_hint = ""
        if auth and getattr(auth, "username", None) and getattr(auth, "password", None):
            auth_hint = (
                "If a login form is present, you may login using these credentials: "
                f"username={getattr(auth, 'username')}, password={getattr(auth, 'password')}. "
            )
        user_prompt = (
            auth_hint
            + "Current page HTML (truncated if long). Suggest one next step. "
            + "Prefer clicking primary links, login, or navigation.\n\n"
            + html[:20000]
        )
        content = self._post_chat([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ])
        try:
            obj = json.loads(content)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        return {"type": "move_only", "x": 100, "y": 100}
