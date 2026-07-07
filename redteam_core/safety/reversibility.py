"""가역성 결정 테이블 (§1.7) — 순수 함수, 결정론.

핵심 불변식(§1.6·C1):
    classify()는 **항상 실행 직전 라이브 물리상태**를 입력으로 받는다.
    계획 시점 캐시값 사용 금지 → TOCTOU(Time-Of-Check to Time-Of-Use) 차단.

판정권은 LLM이 아니라 이 테이블에 있다. SOC의 `core/severity.py`(정책 엔진이
심각도 판정권 보유)와 동형 — "판정은 모델 밖에 산다".
"""

from __future__ import annotations

from typing import Tuple

# gate 값: "none"(무통제) | "low"(자동 허용·기록) | "hitl"(운용자 승인)
#          | "human_only"(인간 전용 hard — 물리 비가역, 자동 경로 없음)
Gate = str


def classify(live_physical_state: dict, action: str) -> Tuple[str, Gate]:
    """(risk_tier, gate)를 반환. live_physical_state = {armed, in_flight, alt_rel, mode}.

    §1.7 결정 테이블:
        on-ground · set_mode(DO_SET_MODE 176)      → 가역        · low
        on-ground · force_arm(ARM 400,p1=1)        → 준가역      · HITL
        in-flight · disarm(400,p1=0)               → 비가역(추락) · 인간 전용
        any       · flight_terminate(185)          → 비가역      · 인간 전용
        any       · takeoff(22)                     → 물리 비가역 · 인간 전용
        any       · param_set_safety(FS_*/ARMING)  → 조건부      · HITL
        in-flight · mission_upload                  → 조건부      · HITL
        any       · gnss_spoof / jam                → 논리가역·물리효과 비가역 가능 · 인간 전용
        read(recon/param_read/telemetry)           → 가역        · none
    """
    in_flight = bool(live_physical_state.get("in_flight"))

    # 읽기 계열 — 상태 불변, 무통제
    if action in ("recon_heartbeat", "param_read", "telemetry_read", "active_scan"):
        return "read", "none"

    if action == "set_mode":
        # on-ground 모드 변경은 즉시 되돌림 가능. 비행 중 모드 변경은 항로/거동에 영향.
        if in_flight:
            return "write_highrisk", "hitl"
        return "write_lowrisk", "low"

    if action == "force_arm":
        # 준가역: disarm 가능하나 추진계 활성. 지상이라도 HITL.
        return "write_highrisk", "hitl"

    if action == "param_set_safety":
        # ARMING_CHECK / FS_* / GEOFENCE 무력화 — 안전장치 제거.
        return "write_highrisk", "hitl"

    if action == "mission_upload":
        return ("write_highrisk", "hitl") if in_flight else ("write_lowrisk", "hitl")

    if action == "disarm":
        # 비행 중 disarm = 모터 정지 = 낙하(비가역). 지상 disarm은 가역.
        if in_flight:
            return "physical_irreversible", "human_only"
        return "write_lowrisk", "low"

    if action in ("takeoff", "flight_terminate"):
        return "physical_irreversible", "human_only"

    if action in ("gnss_spoof", "jam"):
        # 논리적으론 송신 중단 시 가역이나, EKF 발산→실제 거동은 되돌릴 수 없음.
        # 인간 전용 + 물리 안전요원(§1.7).
        return "write_highrisk", "human_only"

    # 온보드-AI 평면(ATLAS AML) — 디지털 공격. 물리 비가역 아님(모터/비행상태 불변).
    # 스테이징/유출은 저위험 자동, 회피/인젝션은 운용영향 커 HITL.
    if action in ("ml_craft_adversarial", "ml_extract_secret"):
        return "write_lowrisk", "low"
    if action in ("ml_evade_perception", "ml_prompt_inject"):
        return "write_highrisk", "hitl"
    if action == "ml_poison_training":
        # 오프라인/공급망 — 런타임 SITL 밖. executor가 스테이징 게이트에서 거부.
        return "write_lowrisk", "staged"

    # 잔여 ATT&CK-ICS 평면 — C2/무인가명령/보고위조/보호무력화. 물리 비가역 아님.
    if action == "c2_common_port":
        return "write_lowrisk", "low"
    if action in ("unauthorized_command", "spoof_telemetry", "disable_protection",
                  "satcom_mitm"):
        return "write_highrisk", "hitl"

    # 미지 액션은 fail-closed: 최고 등급으로 취급.
    return "physical_irreversible", "human_only"


def reversibility_of(risk_tier: str) -> str:
    """risk_tier → reversibility 라벨 (PTGNode 메타 채우기용)."""
    return {
        "read": "reversible",
        "write_lowrisk": "reversible",
        "write_highrisk": "semi_reversible",
        "physical_irreversible": "irreversible",
    }.get(risk_tier, "irreversible")
