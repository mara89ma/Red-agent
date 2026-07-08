"""AI 공격 도구 연동 — PyRIT/Garak (S32 프롬프트인젝션·S33 모델추출).

env AI_ATTACK_PROVIDER(pyrit|garak) + AI_TARGET_URL 지정 시 실 도구로 표적 LLM
공격, 아니면 결정론 폴백(사각지대 모델). 판정권은 모델 밖 유지(조언·실행만).
"""
from __future__ import annotations

import os
from typing import Optional


def _provider() -> str:
    return os.environ.get("AI_ATTACK_PROVIDER", "").lower()


def _target() -> str:
    return os.environ.get("AI_TARGET_URL", "")


def available() -> bool:
    prov, tgt = _provider(), _target()
    if prov not in ("pyrit", "garak") or not tgt:
        return False
    try:
        __import__(prov)          # 지연 임포트(설치 시에만)
        return True
    except Exception:
        return False


def status() -> dict:
    return {"available": available(), "provider": _provider() or None,
            "target": _target() or None,
            "mode": "real" if available() else "fallback"}


def run_ai_attack(technique: str, payload: str = "") -> dict:
    """technique: prompt_injection | model_extraction.

    실연동 시 PyRIT/Garak 로 표적 LLM 공격 실행, 아니면 결정론 폴백.
    """
    mitre = {"prompt_injection": "AML.T0051", "model_extraction": "ATLAS(모델추출)"}
    if available():
        # §T 샌드박스 게이트: 표적이 스코프 내·격리 봉인일 때만 실 실행(fail-closed).
        from ..sandbox import ai_spec, guarded
        return guarded(ai_spec(technique, _target()),
                       lambda: _run_real(technique, payload, mitre.get(technique, "")))
    # 폴백: blue 미매핑(사각지대) — assess 로 일관 판정.
    from ..assessment.bda import assess_action
    action = "ml_prompt_inject" if technique == "prompt_injection" else "ml_extract_secret"
    out = assess_action(action)
    return {"mode": "fallback", "technique": technique, "mitre": mitre.get(technique),
            "detected": out.detected, "note": "결정론 폴백(사각지대) — 실 도구 미연동"}


def _run_real(technique: str, payload: str, mitre: str) -> dict:  # pragma: no cover
    """실 PyRIT/Garak 실행 경로(설치·표적 있을 때만). 여기선 미실행."""
    prov = _provider()
    # 실제 구현: pyrit PromptSendingOrchestrator / garak probe 를 _target() 에 실행.
    # (설치·표적 필요 → 본선/실환경에서 활성)
    return {"mode": "real", "provider": prov, "technique": technique, "mitre": mitre,
            "target": _target(), "note": "실 도구 실행 경로(env 활성)"}
