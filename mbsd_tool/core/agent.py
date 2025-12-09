from __future__ import annotations

import json
from typing import Any, Dict, List

import httpx


SYSTEM_PROMPT = """You are a professional web security testing agent. Your goal is to autonomously discover vulnerabilities by navigating a web application like a human tester.

You will be given a high-level `GOAL`, the `HISTORY` of your previous actions, and the current page's `HTML`.
You must respond with a JSON object containing your `thought` process and the next `action` to take.

**RESPONSE JSON SCHEMA:**
{
  "thought": "A brief explanation of your reasoning for the next action. Why are you taking this step towards the goal?",
  "action": {
    "type": "<action_type>",
    "selector": "<CSS selector for the target element>",
    "url": "<URL for navigation>",
    "fields": { "<input_selector>": "<value>" },
    "key": "<memory key>",
    "value": "<memory value>",
    "text": "<text to assert>",
    "present": "<boolean for assertion>",
    "success": "<boolean for finish>",
    "message": "<final message for finish>"
  }
}

**AVAILABLE ACTIONS:**
- `navigate(url)`: Go to a specific URL.
- `click(selector, description)`: Click on an element matching a CSS selector. `description` is a short text description of the element.
- `fill_form(selector, fields)`: Fill form fields within an element matching a CSS selector. `fields` is a dictionary of `{ "input_selector": "value" }`.
- `submit_form(selector)`: Submit a form.
- `memory_set(key, value)`: Store a value in your memory for later use.
- `memory_get(key)`: Retrieve a value from your memory.
- `assert_text(text, present)`: Check if a specific text is present (`present: true`) or not (`present: false`) on the page.
- `finish(success, message)`: Terminate the test scenario with a success/failure status and a final message.
"""


class AgentClient:
    def __init__(self, base_url: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.history: List[Dict[str, Any]] = []
        self.memory: Dict[str, Any] = {}

    def _post_chat(self, messages: list[dict[str, str]]) -> str:
        # Ollama chat API
        url = f"{self.base_url}/api/chat"
        payload = {"model": self.model, "messages": messages, "stream": False, "format": "json"}
        try:
            r = httpx.post(url, json=payload, timeout=30.0) # Increased timeout for complex reasoning
            r.raise_for_status()
            data = r.json()
            return data.get("message", {}).get("content", "")
        except Exception as e:
            # Fallback with error
            return json.dumps({"thought": f"Error communicating with LLM: {e}", "action": {"type": "finish", "success": False, "message": "LLM communication failed."}})

    def execute_step(self, goal: str, html: str) -> Dict[str, Any]:
        user_prompt = f"GOAL: {goal}\n\nHISTORY:\n{json.dumps(self.history, indent=2)}\n\nMEMORY:\n{json.dumps(self.memory, indent=2)}\n\nCURRENT PAGE HTML (truncated):\n{html[:15000]}"
        
        content = self._post_chat([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ])
        
        try:
            response_obj = json.loads(content)
            if not isinstance(response_obj, dict) or "action" not in response_obj:
                raise ValueError("Invalid JSON response from LLM")
        except Exception as e:
            # If LLM fails to produce valid JSON, finish the run
            response_obj = {"thought": f"Failed to parse LLM response: {e}. Content: {content}", "action": {"type": "finish", "success": False, "message": "LLM response was not valid JSON."}}

        action = response_obj.get("action", {})
        thought = response_obj.get("thought", "(No thought provided)")

        # Persist thought and action to history
        self.history.append({"thought": thought, "action": action})

        # Process memory actions internally
        if action.get("type") == "memory_set":
            key, value = action.get("key"), action.get("value")
            if key:
                self.memory[key] = value
            # This action is internal, so we immediately decide the next one
            return self.execute_step(goal, html)
        if action.get("type") == "memory_get":
            # This is tricky in a single-turn setup. The LLM can't get the value in the same turn.
            # A better design would be a multi-turn conversation or function calling.
            # For now, we'll just acknowledge it and move on. The LLM should use the MEMORY context in the next prompt.
            return self.execute_step(goal, html)

        return response_obj
