from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel


class ScanMode(str, Enum):
    SAFE = "セーフ"
    NORMAL = "通常"
    ATTACK = "攻撃"


class VulnerabilityFinding(BaseModel):
    name: str
    severity: str
    evidence: Optional[str] = None
    reproduction_steps: Optional[List[str]] = None


class ScanResult(BaseModel):
    target: str
    mode: ScanMode
    endpoints: List[str]
    vulns_by_endpoint: Dict[str, List[VulnerabilityFinding]]


class AuthConfig(BaseModel):
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
