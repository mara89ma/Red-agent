"""blue 탐지 룰 스펙 — dah-sentinel-content 의 실제 S1~S28 KQL 에서 씨앗 추출.

D8 준수: 여기 담기는 것은 blue 의 룰 정의(공유 산출물)에서 **수동 씨앗 복사**한
임계/조건일 뿐, pollack-ai(SOC 에이전트) 코드도 룰 repo 런타임 의존도 아니다.
각 스펙에 출처(파일·triggerThreshold)를 provenance 로 명시한다.

임계 위치 참고(정정): blue 룰 임계는 대부분 `UAV_Threshold_List` watchlist 로
외부화(ThresholdKey/Value) 돼 있어 §A 보정값을 watchlist 갱신으로 반영 가능하다.
단 아래 씨앗 중 S6(FailCount>=5/3)·S1(zScore=3.0·gateMultiplier=1.5)은 쿼리
리터럴이라, 이 둘의 보정은 쿼리 임계 수정이 필요하다.

`kind`:
  - continuous : 임계가 연속값 → red 가 강도를 낮춰 탐지 경계를 이분 탐색 가능(보정 대상).
  - categorical : 논리 확정(자기승인·비인가 등) → 강도 조절로 회피 불가. red 는 TTP 전환 필요.

교리 라벨(장기 C 대비 선삽입):
  - d4m : JP 3-12 공격효과 (Deny=Degrade/Disrupt/Destroy | Manipulate | Collect)
  - jp360_phase : 이 액션이 속하는 조인트 타게팅 단계(주로 ⑤ 실행)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class RuleSpec:
    rule_id: str
    table: str
    kind: str                       # "continuous" | "categorical"
    # continuous: 탐지 경계(이 값 이상이면 탐지). blue 가상값/실측 씨앗.
    threshold: Optional[float] = None
    threshold_param: str = "intensity"
    # 관측 행(observable)에서 탐지여부를 판정하는 술어.
    predicate: Optional[Callable[[dict], bool]] = None
    d4m: str = ""
    jp360_phase: str = "⑤ 실행"
    provenance: str = ""            # dah-sentinel-content 출처


def _ge(param: str, thr: float) -> Callable[[dict], bool]:
    return lambda row: float(row.get(param, 0.0)) >= thr


# ── S1~S18 씨앗 (실제 룰에서 추출) ────────────────────────────────────────────
# 값 출처는 provenance 에 명시. 연속 룰이 폐루프 임계 보정의 핵심 대상.
DETECTION_RULES: Dict[str, RuleSpec] = {
    "S1_GNSS_Spoofing": RuleSpec(
        rule_id="S1_GNSS_Spoofing", table="UAVTelemetry_CL", kind="continuous",
        # 동적 게이트 = P99(PosHorizVariance<1.0, 24h) x 1.5. 측정 베이스라인 P99≈0.0159.
        threshold=0.0238, threshold_param="pos_horiz_variance",
        predicate=_ge("pos_horiz_variance", 0.0238),
        d4m="Manipulate", jp360_phase="⑤ 실행",
        provenance="S1_GNSS_Spoofing.json: dynamicPosGate=P99(<1.0)x1.5, zScore=3.0"),

    "S6_Operator_BruteForce": RuleSpec(
        rule_id="S6_Operator_BruteForce", table="UAVOpAudit_CL", kind="continuous",
        threshold=5.0, threshold_param="fail_count_per_min",
        predicate=_ge("fail_count_per_min", 5.0),
        d4m="Deny(Disrupt)", jp360_phase="② 표적개발/접근",
        provenance="S6_Operator_BruteForce.json: FailCount>=5 by ClientIp, bin 1m"),

    "S18_MAVLink_Unsigned_Burst": RuleSpec(
        rule_id="S18_MAVLink_Unsigned_Burst", table="UAVMavsec_CL", kind="continuous",
        # 실제는 series_decompose z-score(3.0). 여기선 baseline 대비 배수를 강도 프록시로.
        threshold=5.0, threshold_param="unsigned_count",
        predicate=_ge("unsigned_count", 5.0),
        d4m="Collect", jp360_phase="② 표적개발/접근",
        provenance="S18_MAVLink_Unsigned_Burst.json: zThreshold=3.0 on AvgUnsigned + FailedCount>0"),

    "S11_Unauthorized_Weapon_Cmd": RuleSpec(
        rule_id="S11_Unauthorized_Weapon_Cmd", table="UAVWeapon_CL", kind="categorical",
        predicate=lambda row: bool(
            row.get("is_self_approval") or row.get("is_unknown_op") or row.get("is_unknown_weapon")),
        d4m="Deny(Destroy)", jp360_phase="⑤ 실행",
        provenance="S11_Unauthorized_Weapon_Cmd.json: isSelfApproval or isUnknownOp or isUnknownWeapon"),

    "S15_OffHours_C4I_Cmd": RuleSpec(
        rule_id="S15_OffHours_C4I_Cmd", table="UAVC4I_CL", kind="categorical",
        predicate=lambda row: bool(row.get("offhours") and row.get("unauthorized")),
        d4m="Manipulate", jp360_phase="⑤ 실행",
        provenance="S15_OffHours_C4I_Cmd.json: off-hours issuance by non-approved command"),
}


# ── red 원자 액션 → 이를 관측하는 blue 룰 ─────────────────────────────────────
# 동언님 tools/mavlink.py·ics_actions.py·ml_target.py 의 액션명 기준.
_ACTION_RULE: Dict[str, str] = {
    "gnss_spoof": "S1_GNSS_Spoofing",
    "force_arm": "S11_Unauthorized_Weapon_Cmd",     # 무장/시동 계열 → 무장 룰로 관측
    "unauthorized_command": "S15_OffHours_C4I_Cmd",
    "active_scan": "S6_Operator_BruteForce",         # 자격증명/스캔 → 브루트포스 관측(근사)
    "spoof_telemetry": "S18_MAVLink_Unsigned_Burst",
}


def action_to_rule(action: str) -> Optional[RuleSpec]:
    rid = _ACTION_RULE.get(action)
    return DETECTION_RULES.get(rid) if rid else None
