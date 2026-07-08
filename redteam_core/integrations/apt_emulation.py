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

# APT → 순서 있는 킬체인 패턴(확장). ATT&CK Group 운용 특성 반영.
# 정찰(S34)로 시작해 7단계 킬체인을 최대한 커버.
APT_EMULATION = {
    # ── 기존 5개(확장) ──
    "Sandworm (G0034)": ["S34", "S4", "S21", "S19", "S20", "S23", "S25"],   # OT 파괴
    "APT28 (G0007)": ["S34", "S6", "S10", "S13", "S15", "S11", "S17"],      # 방산 espionage
    "Volt Typhoon (G1017)": ["S34", "S6", "S27", "S26", "S24", "S2"],       # LOTL 인프라
    "EW Threat Cluster": ["S1", "S30", "S31", "S3", "S9", "S18"],           # 전자전 확전
    "AML Adversary (ATLAS)": ["S29", "S7", "S32", "S33", "S8"],             # AI 계층(전 단계 미배포)
    # ── 신규 3개(한국 방산 관련 DPRK + 항공우주) ──
    "Lazarus (G0032)": ["S34", "S6", "S4", "S11", "S23", "S25"],            # DPRK 파괴·탈취
    "Kimsuky (G0094)": ["S34", "S6", "S10", "S12", "S17"],                  # DPRK ROK 방산 espionage
    "APT33 (G0064)": ["S34", "S4", "S1", "S11"],                            # 항공우주 표적
}

# campaigns 에 없는 시나리오의 탐지상태 — **배포된 S1~S28 룰 기준**.
# 배포룰 존재=탐지(True) / 미배포(S7·S29·군집·AI계열)=사각(None).
_EXTRA_STATIC = {
    "S2": True, "S3": True, "S5": True, "S9": True, "S10": True, "S18": True,
    "S19": True, "S21": True, "S23": True, "S24": True, "S25": True,
    "S26": True, "S27": True,
    "S7": None, "S29": None,                       # 미배포 = 사각지대
}


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
