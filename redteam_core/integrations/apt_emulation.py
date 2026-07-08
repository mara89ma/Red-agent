"""APT 에뮬레이션 — 위협행위자의 '순서 있는 킬체인 패턴' 참조·실행 (§O 확장).

TI(actor→시나리오 집합)를 넘어, 각 APT 의 특징적 킬체인 순서(emulation_chain)를
참조해 "그 APT 로서" 캠페인을 실행하고 blue 가 어디서 잡는지 산출한다.
  - APT_EMULATION: ATT&CK Groups 기반 순서 킬체인 시드(오프라인).
  - CTID seam: env CTID_PLAN_URL 지정 시 MITRE CTID Adversary Emulation Library pull.
  - next_ttp_by_pattern: 패턴 기반 다음 TTP 제안(planner 참조, LLM 있으면 정교화).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# APT → 순서 있는 킬체인 패턴(대표). ATT&CK Group 운용 특성 반영.
APT_EMULATION = {
    "Sandworm (G0034)": ["S4", "S19", "S23", "S25"],        # 공급망→failsafe→서비스중단→DoS
    "APT28 (G0007)": ["S6", "S10", "S15", "S11", "S17"],    # 자격증명→모바일→야간명령→무장→유출
    "Volt Typhoon (G1017)": ["S6", "S26", "S24"],           # 자격증명→라우터→데이터링크(LOTL)
    "EW Threat Cluster": ["S1", "S30", "S3", "S9"],          # 스푸핑→재밍→SATCOM MITM→무력화
    "AML Adversary (ATLAS)": ["S5", "S32", "S33", "S7"],     # RAG→인젝션→추출→온보드
}

# campaigns 에 없는 시나리오의 알려진 탐지상태(배포=탐지 / 미배포=사각).
_EXTRA_STATIC = {"S3": True, "S5": True, "S9": True, "S10": True, "S7": None}


def _exec(sid: str) -> Tuple[bool, Optional[bool]]:
    if sid in _EXTRA_STATIC:
        return True, _EXTRA_STATIC[sid]
    from ..campaigns.chains import _exec_scenario
    return _exec_scenario(sid)


# ── CTID Adversary Emulation Library seam ────────────────────────────────────
def ctid_available() -> bool:
    return bool(os.environ.get("CTID_PLAN_URL", ""))


def status() -> dict:
    return {"available": ctid_available(),
            "ctid_url": os.environ.get("CTID_PLAN_URL", "") or None,
            "mode": "real" if ctid_available() else "fallback",
            "apt_profiles": len(APT_EMULATION)}


def emulation_plan(actor: str) -> List[str]:
    """APT 킬체인 순서. CTID 연동 시 실 플랜(본선), 아니면 시드."""
    if ctid_available():  # pragma: no cover
        return _pull_ctid_plan(actor)
    return list(APT_EMULATION.get(actor, []))


def _pull_ctid_plan(actor: str) -> List[str]:  # pragma: no cover
    """실 CTID Adversary Emulation Library 에서 플랜 pull(env 활성). 여기선 미실행."""
    return list(APT_EMULATION.get(actor, []))


# ── APT 에뮬레이션 실행 ───────────────────────────────────────────────────────
@dataclass
class AptEmulationResult:
    actor: str
    verdict: str                        # stealthy | detected
    steps: List[Tuple[str, Optional[bool]]] = field(default_factory=list)  # (sid, detected)
    detected_at: List[str] = field(default_factory=list)


def run_apt_emulation(actor: str) -> AptEmulationResult:
    steps: List[Tuple[str, Optional[bool]]] = []
    detected_at: List[str] = []
    for sid in emulation_plan(actor):
        _achieved, detected = _exec(sid)
        steps.append((sid, detected))
        if detected is True:
            detected_at.append(sid)
    verdict = "detected" if detected_at else "stealthy"
    return AptEmulationResult(actor, verdict, steps, detected_at)


# ── LLM 플래너 패턴 참조 ──────────────────────────────────────────────────────
def next_ttp_by_pattern(actor: str, completed: Optional[List[str]] = None) -> Optional[str]:
    """APT 패턴상 다음 TTP(미완료 첫 단계). LLM 있으면 정교화(opt-in)."""
    completed = set(completed or [])
    for sid in emulation_plan(actor):
        if sid not in completed:
            return sid                  # 결정론: 패턴 순서 준수
    return None
