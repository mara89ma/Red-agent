"""타깃 지문 (B7) — 결정론 엔티티 클러스터링.

명시적 host id가 있으면 그대로, 없으면 (마스킹 IP·서비스 포트) 정규화 차원으로
`fp:<sha256-16>` 지문을 만든다. 빈 페이로드는 고정 빈 키 → 게이트가 거부(무한 충돌
방지). pollack `actor_fingerprint.py`의 공격판.
"""

from __future__ import annotations

import hashlib

_EMPTY_KEY = "target:empty"


def _mask24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip


def resolve_target_id(profile: dict) -> tuple[str, bool]:
    """(target_id, is_explicit) 반환. 명시 host id면 explicit=True."""
    tp = profile.get("target_profile", {})
    hosts = tp.get("hosts") or []
    if hosts and hosts[0].get("id"):
        return str(hosts[0]["id"]), True

    svcs = tp.get("services") or []
    ips = sorted({_mask24(s["ip"]) for s in svcs if s.get("ip")})
    ports = sorted({s["port"] for s in svcs if s.get("port")})
    if not ips and not ports:
        return _EMPTY_KEY, False
    basis = repr((ips, ports))
    return "fp:" + hashlib.sha256(basis.encode()).hexdigest()[:16], False


def is_empty_target(target_id: str) -> bool:
    return target_id == _EMPTY_KEY
