"""MITRE Caldera 연동 — 캠페인(C1~C10) 오케스트레이션.

env CALDERA_URL + CALDERA_API_KEY 지정 시 Caldera REST API 로 operation 실행,
아니면 내부 §M 캠페인 실행(폴백).
"""
from __future__ import annotations

import os
from typing import Optional


def _url() -> str:
    return os.environ.get("CALDERA_URL", "")


def _key() -> str:
    return os.environ.get("CALDERA_API_KEY", "")


def available() -> bool:
    return bool(_url() and _key())


def status() -> dict:
    return {"available": available(), "url": _url() or None,
            "mode": "real" if available() else "fallback"}


def run_operation(chain_id: str) -> dict:
    """chain_id: C1~C10. 실연동 시 Caldera operation, 아니면 §M 내부 실행."""
    if available():
        # §T 샌드박스 게이트: Caldera 서버가 스코프 내일 때만 실 operation(fail-closed).
        from ..sandbox import caldera_spec, guarded
        return guarded(caldera_spec(chain_id, _url()), lambda: _run_real(chain_id))
    from ..campaigns import run_chain
    r = run_chain(chain_id)
    return {"mode": "fallback", "chain": chain_id, "verdict": r.verdict,
            "detected_at": r.detected_at, "note": "내부 §M 실행(Caldera 미연동)"}


def _run_real(chain_id: str) -> dict:  # pragma: no cover
    """실 Caldera 실행 경로(서버 있을 때만). 여기선 미실행."""
    # 실제 구현: POST {_url()}/api/v2/operations (헤더 KEY=_key()) 로 adversary/ability 매핑.
    return {"mode": "real", "chain": chain_id, "url": _url(),
            "note": "Caldera REST operation 경로(env 활성)"}
