from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass
class Settings:
    ollama_base_url: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.1:latest")

    @classmethod
    def load(cls) -> "Settings":
        return cls()

