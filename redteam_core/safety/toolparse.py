"""생 툴 출력 재투입 금지 → 스키마 제약 필드만 추출 (§2.8 toolparse.py).

간접 인젝션 방어(2601.04795: ASR 26%→0.5%). 스푸핑 텔레메트리가 모델
프롬프트로 그대로 흘러들지 않게 한다. 원시 출력은 append-only 감사로만 보존.
"""

from __future__ import annotations

from typing import Iterable


def extract(raw: dict, allowed_fields: Iterable[str]) -> dict:
    """allowed_fields만 화이트리스트 추출. 그 외 키는 폐기(프롬프트 오염 차단)."""
    allowed = set(allowed_fields)
    return {k: v for k, v in raw.items() if k in allowed}


def prune_telemetry(lines: list, keep: int = 10) -> list:
    """텔레메트리 라인 가지치기(Summarizer 보조) — 최근 k만, 생값은 감사로."""
    return list(lines[-keep:])
