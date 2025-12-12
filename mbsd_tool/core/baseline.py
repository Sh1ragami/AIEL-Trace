from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Tuple, Dict, Set

from mbsd_tool.core.models import ScanResult, VulnerabilityFinding


def _finding_key(endpoint: str, v: VulnerabilityFinding) -> str:
    """Generate a stable key for a finding to match across scans.

    We intentionally avoid volatile fields (severity/evidence).
    """
    name = (v.name or "").strip()
    category = (v.category or "").strip()
    selector = (v.element_selector or "").strip()
    # endpoint + name + category + selector is a reasonable compromise
    # (avoid severity/evidence/test_type as they can change across scans)
    return "||".join([endpoint.strip(), name, category, selector])


def build_baseline(result: ScanResult) -> dict:
    """Build a baseline JSON-serializable object from a ScanResult."""
    items: List[dict] = []
    for endpoint, vulns in result.vulns_by_endpoint.items():
        for v in vulns:
                items.append({
                    "endpoint": endpoint,
                    "name": v.name,
                    "category": v.category,
                    "element_selector": v.element_selector,
                    "key": _finding_key(endpoint, v),
                })
    return {
        "version": 1,
        "target": result.target,
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "items": items,
    }


def save_baseline(result: ScanResult, path: str | Path) -> None:
    p = Path(path)
    data = build_baseline(result)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _keys_from_result(result: ScanResult) -> Set[str]:
    keys: Set[str] = set()
    for endpoint, vulns in result.vulns_by_endpoint.items():
        for v in vulns:
            keys.add(_finding_key(endpoint, v))
    return keys


def load_baseline(path: str | Path) -> dict:
    """Load a baseline file. Supports either our baseline schema or raw ScanResult JSON."""
    p = Path(path)
    obj = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(obj, dict) and {"version", "items"}.issubset(set(obj.keys())):
        # Already our baseline schema
        return obj
    # Otherwise try to interpret as ScanResult schema
    try:
        items: List[dict] = []
        target = obj.get("target")
        for endpoint, vulns in (obj.get("vulns_by_endpoint") or {}).items():
            for v in vulns:
                items.append({
                    "endpoint": endpoint,
                    "name": v.get("name"),
                    "category": v.get("category"),
                    "element_selector": v.get("element_selector"),
                    "key": "||".join([
                        endpoint.strip(),
                        (v.get("name") or "").strip(),
                        (v.get("category") or "").strip(),
                        (v.get("element_selector") or "").strip(),
                    ]),
                })
        return {
            "version": 1,
            "target": target,
            "generated_at": None,
            "items": items,
        }
    except Exception as e:
        raise ValueError("Unsupported baseline file format") from e


def diff_against_baseline(prev_baseline: dict, current: ScanResult) -> dict:
    """Compute diff between a previous baseline and current result.

    Returns a dictionary with lists: new, unresolved, fixed, and counts.
    """
    prev_items: List[dict] = prev_baseline.get("items", []) if isinstance(prev_baseline, dict) else []
    prev_keys: Set[str] = {it.get("key") for it in prev_items if it.get("key")}
    cur_map: Dict[str, Tuple[str, VulnerabilityFinding]] = {}
    cur_keys: Set[str] = set()
    for endpoint, vulns in current.vulns_by_endpoint.items():
        for v in vulns:
            k = _finding_key(endpoint, v)
            cur_keys.add(k)
            cur_map[k] = (endpoint, v)

    new_keys = cur_keys - prev_keys
    unresolved_keys = cur_keys & prev_keys
    fixed_keys = prev_keys - cur_keys

    def _select(entries: Iterable[str]) -> List[dict]:
        out: List[dict] = []
        for k in entries:
            if k in cur_map:
                ep, v = cur_map[k]
                out.append({
                    "endpoint": ep,
                    "name": v.name,
                    "severity": v.severity,
                    "category": v.category,
                    "element_selector": v.element_selector,
                    "key": k,
                })
        return out

    # For fixed, use prev items
    fixed: List[dict] = []
    for it in prev_items:
        k = it.get("key")
        if k and k in fixed_keys:
            fixed.append({
                "endpoint": it.get("endpoint"),
                "name": it.get("name"),
                "category": it.get("category"),
                "element_selector": it.get("element_selector"),
                "key": k,
            })

    new_list = _select(sorted(new_keys))
    unresolved_list = _select(sorted(unresolved_keys))

    return {
        "summary": {
            "new": len(new_list),
            "unresolved": len(unresolved_list),
            "fixed": len(fixed),
        },
        "new": new_list,
        "unresolved": unresolved_list,
        "fixed": fixed,
    }
