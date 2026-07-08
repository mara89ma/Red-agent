"""RoE 게이트 — 교전권한·RoE 조건·데컨플릭션을 합성한 결정론 판정.

동언님 reversibility 게이트(안전)와 합성: reversibility 는 gate 강도를, 여기서는
그 위에 권한 레벨·PID·ConOps·데컨플릭션을 얹어 최종 교전 가부를 낸다.
판정은 모델 밖(결정론) — DoDD 3000.09.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from ..safety.reversibility import classify
from .authority import AuthorityLevel, required_authority
from .cde import CdeTier, estimate_cde
from .deconfliction import check_deconfliction

# 액션 → JP 3-12 공격효과(D4M). ConOps 허용효과 대조에 사용.
ACTION_EFFECT = {
    "recon_heartbeat": "Collect", "param_read": "Collect", "active_scan": "Collect",
    "spoof_telemetry": "Manipulate", "gnss_spoof": "Manipulate", "satcom_mitm": "Collect",
    "set_mode": "Manipulate", "force_arm": "Deny(Destroy)", "param_set_safety": "Manipulate",
    "mission_upload": "Manipulate", "takeoff": "Deny(Disrupt)", "disarm": "Deny(Destroy)",
    "flight_terminate": "Deny(Destroy)", "jam": "Deny(Disrupt)", "unauthorized_command": "Manipulate",
}


class RoeVerdict(str, Enum):
    PERMITTED = "PERMITTED"    # 위임 권한 내 + 조건 충족 → 자동 진행 가능
    ESCALATE = "ESCALATE"      # 조건 충족하나 상급 권한 필요 → 승인 상신
    BLOCKED = "BLOCKED"        # RoE 위반/데컨플릭션 실패 → 교전 불가


@dataclass
class RoeDecision:
    action: str
    verdict: RoeVerdict
    required_authority: str
    available_authority: str
    cde_tier: str
    effect: str
    unmet_conditions: List[str] = field(default_factory=list)
    deconfliction_conflicts: List[str] = field(default_factory=list)
    rationale: str = ""
    doctrine_refs: List[str] = field(default_factory=list)


def evaluate_roe(action: str, live_physical_state: dict, target: dict,
                 profile: dict) -> RoeDecision:
    risk_tier, gate = classify(live_physical_state, action)
    cde = estimate_cde(action, live_physical_state)
    req = required_authority(gate, cde)
    avail = _authority(profile.get("available_authority", "COMPONENT"))
    effect = ACTION_EFFECT.get(action, "Manipulate")

    unmet: List[str] = []
    # PID(적극식별) — 공격 계열은 표적 PID 필수(SROE).
    if risk_tier in set(profile.get("pid_required_for", [])) and not target.get("pid"):
        unmet.append("PID 미충족: 적극식별(positive ID) 없음 (SROE)")
    # ConOps 임무범위 — 허용 효과 밖이면 위반.
    permitted = profile.get("conops", {}).get("permitted_effects")
    if permitted is not None and effect not in set(permitted):
        unmet.append(f"ConOps 범위 밖 효과: {effect} ∉ {permitted}")

    decon = check_deconfliction(action, target, profile)

    # 판정 순서: 조건/데컨플릭션 위반 → BLOCKED, 아니면 권한 초과 → ESCALATE.
    if unmet or not decon.ok:
        verdict, rationale = RoeVerdict.BLOCKED, "RoE 조건/데컨플릭션 위반 — 교전 불가"
    elif req > avail:
        verdict = RoeVerdict.ESCALATE
        rationale = f"권한 상신 필요: 요구 {req.name} > 위임 {avail.name}"
    else:
        verdict, rationale = RoeVerdict.PERMITTED, "위임 권한 내 · 조건 충족"

    return RoeDecision(
        action=action, verdict=verdict,
        required_authority=req.name, available_authority=avail.name,
        cde_tier=cde.name, effect=effect,
        unmet_conditions=unmet, deconfliction_conflicts=decon.conflicts,
        rationale=rationale,
        doctrine_refs=["SROE CJCSI 3121.01", "JP 3-60 ④", "CJCSM 3160 CDE",
                       "JP 3-85 JEMSO", "DoDD 3000.09"])


def _authority(name: str) -> AuthorityLevel:
    try:
        return AuthorityLevel[str(name).upper()]
    except KeyError:
        return AuthorityLevel.COMPONENT


def load_roe_profile(path: str = "") -> dict:
    """RoE 프로파일 YAML 로드. 미설정/미설치 시 보수적 기본값(무음 폴백)."""
    path = path or os.environ.get("ROE_PROFILE", "")
    if path:
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return _DEFAULT_ROE_PROFILE


# 보수적 기본 프로파일(위임 권한 낮음·스펙트럼 미승인 = fail-safe).
_DEFAULT_ROE_PROFILE = {
    "available_authority": "COMPONENT",
    "conops": {"mission": "UAS 레드팀 평가(기본)",
               "permitted_effects": ["Collect", "Manipulate", "Deny(Disrupt)"]},
    "pid_required_for": ["write_highrisk", "physical_irreversible"],
    "no_strike_list": [1, 254, 255],
    "restricted_targets": [],
    "spectrum": {"jceoi_deconflicted": False},
}
