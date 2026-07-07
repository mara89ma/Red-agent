"""(7) Summarizer — 텔레메트리 라인 가지치기 (§1.3·§2.8).

생 텔레메트리는 프롬프트 밖 append-only(증거). 모델엔 최근 k만.
"""

from __future__ import annotations

from ..safety import toolparse


def summarizer(state) -> dict:
    window = toolparse.prune_telemetry(state.get("audit_log", []), keep=10)
    return {"telemetry_window": window}
