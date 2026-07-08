"""CVE 인텔 연동 — cve-mcp-server MCP seam (§Q).

env CVE_MCP_URL(cve-mcp-server 게이트웨이) 지정 시 라이브 CVE 조회(NVD 기반),
아니면 §V dronesploit 정적 CVE 레지스트리로 폴백. 표적 자산의 CVE를 §F 표적개발에
반영(취약성 정보).

안전: 조회 전용(읽기). 실 조회는 §T 샌드박스 통과 시에만(fail-closed).
"""
from __future__ import annotations

import os
from typing import List, Optional


def _url() -> str:
    return os.environ.get("CVE_MCP_URL", "")


def available() -> bool:
    return bool(_url())


def status() -> dict:
    return {"available": available(), "endpoint": _url() or None,
            "mode": "real" if available() else "fallback"}


def lookup_cve(cve_id: str) -> dict:
    """CVE 상세 조회. 실연동 시 MCP, 아니면 정적 레지스트리."""
    if available():
        from ..sandbox import guarded
        from urllib.parse import urlparse
        u = urlparse(_url() if "://" in _url() else "http://" + _url())
        spec = {"name": f"cve:{cve_id}", "network": [(u.hostname or _url(), u.port or 443)]}
        return guarded(spec, lambda: _query_real(cve_id))
    from ..dronesploit.cve import DRONE_CVES
    hit = next((c for c in DRONE_CVES if c["cve"] == cve_id), None)
    return {"mode": "fallback(static)", "cve": cve_id, "record": hit,
            "note": "CVE_MCP_URL 미설정 → 정적 레지스트리 조회"}


def cves_for_scenario(scenario_id: str) -> List[dict]:
    """시나리오 관련 CVE(정적 §V 레지스트리 + 라이브 확장 가능)."""
    from ..dronesploit.cve import cves_for
    return cves_for(scenario_id)


def _query_real(cve_id: str) -> dict:  # pragma: no cover
    """실 cve-mcp-server 조회(게이트웨이 있을 때만). 여기선 미실행."""
    # MCP: POST {CVE_MCP_URL}/tools/get_cve {"cve_id": cve_id} → NVD 상세.
    return {"mode": "real", "cve": cve_id, "endpoint": _url()}
