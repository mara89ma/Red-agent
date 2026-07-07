"""(5b) 검증 킬체인 playbook RAG (§1.4(5)·§2.3 procedural).

추상 액션 = 계획 단위(Incalmo 2501.16466). Planner가 `hijack` 같은 묶음을 1개
추상 노드로 추론하고, 여기 정의된 **원자 액션 시퀀스로 즉시 전개**한다(§1.6).
각 항목: 조건 + 검증(expected_effect) + 승인. untrusted.
"""

from __future__ import annotations

from ..tools.mavlink import FLIGHT_MODE

# 추상 액션 → 원자 노드 시퀀스. 각 스텝은 (action, params, expected_effect).
PLAYBOOKS = {
    # A4 평문 인젝션 킬체인 — 무인증 5790 → 제어 획득 → (게이트 도달)미션킬 능력.
    "A4_force_arm_takeoff": {
        "technique": "T1692.001",
        "scenario": "A4",
        "steps": [
            ("recon_heartbeat", [], {"type": "recon"}),
            ("set_mode", [1, FLIGHT_MODE["GUIDED"]],
             {"type": "set_mode", "mode_id": FLIGHT_MODE["GUIDED"]}),
            ("force_arm", [1, 0], {"type": "arm"}),
            ("takeoff", [0, 0, 0, 0, 0, 0, 10.0],
             {"type": "takeoff", "alt_threshold": 2.0}),   # 물리 비가역 → 인간 전용 게이트
        ],
    },
    # S1 GNSS 스푸핑 (병렬 분기) — 성공=드론이 믿는 위치가 진짜와 괴리(§2.7).
    "S1_gnss_spoof": {
        "technique": "T0835",
        "scenario": "S1",
        "steps": [
            ("recon_heartbeat", [], {"type": "recon"}),
            ("gnss_spoof", [], {"type": "gnss_spoof", "target_drift_m": 50.0}),
        ],
    },
    # M1 온보드 인지 회피 (ATLAS) — 적대적 데이터 제작(T0043) → 인지모델 회피(T0015).
    # 성공=모델 출력이 실제 대상과 괴리(장애물→'없음'). GNSS 스푸핑과 동형 검증.
    "M1_perception_evasion": {
        "technique": "AML.T0015",
        "scenario": "M1",
        "steps": [
            ("recon_heartbeat", [], {"type": "recon"}),
            ("ml_craft_adversarial", [], {"type": "ml_craft"}),      # AML.T0043 스테이징
            ("ml_evade_perception", [], {"type": "ml_evade"}),       # AML.T0015 회피
        ],
    },
    # M2 코파일럿 인젝션→유출 (ATLAS) — 프롬프트 인젝션(T0051)으로 가드레일 우회 후
    # 시크릿 유출(T0057). 성공=실제 시크릿이 빠져나감(디코이는 오탐 회피로 판정).
    "M2_copilot_exfil": {
        "technique": "AML.T0057",
        "scenario": "M2",
        "steps": [
            ("recon_heartbeat", [], {"type": "recon"}),
            ("ml_prompt_inject", [], {"type": "ml_inject"}),         # AML.T0051 인젝션
            ("ml_extract_secret", [], {"type": "ml_leak"}),          # AML.T0057 유출
        ],
    },
    # R1 정찰→은닉 C2 (ICS) — 액티브 스캔(T1595)으로 오픈 포트 확인 후 상용 포트 C2(T0885).
    "R1_recon_c2": {
        "technique": "T0885",
        "scenario": "R1",
        "steps": [
            ("active_scan", [], {"type": "ics_scan"}),               # T1595 정찰
            ("c2_common_port", [], {"type": "ics_c2"}),              # T0885 상용포트 C2
        ],
    },
    # E1 무인가 명령→보고 위조 (ICS) — 무인가 액추에이터 명령(T0855) 후 텔레메트리 위조로
    # 오퍼레이터 눈속임(T0856). 성공=오퍼레이터가 거짓 정상 상태를 봄(지상계측과 괴리).
    "E1_spoof_command": {
        "technique": "T0856",
        "scenario": "E1",
        "steps": [
            ("recon_heartbeat", [], {"type": "recon"}),
            ("unauthorized_command", [], {"type": "ics_uc"}),        # T0855 무인가 명령
            ("spoof_telemetry", [], {"type": "ics_spoof"}),          # T0856 보고 위조
        ],
    },
    # I1 보호 무력화 (ICS) — 실패세이프/지오펜스 무력화(T0837, impact). 성공=보호 상실.
    "I1_loss_protection": {
        "technique": "T0837",
        "scenario": "I1",
        "steps": [
            ("recon_heartbeat", [], {"type": "recon"}),
            ("disable_protection", [], {"type": "ics_lop"}),         # T0837 보호 무력화
        ],
    },
    # L1 SATCOM/BLOS 링크 MITM (ICS) — AiTM(T0830)로 세션 무결성 침해→제어조작(T0831).
    # 성공=링크 무결성 실제 상실. 하드닝(링크 암호화/상호인증)은 거부.
    "L1_satcom_mitm": {
        "technique": "T0830",
        "scenario": "L1",
        "steps": [
            ("recon_heartbeat", [], {"type": "recon"}),
            ("satcom_mitm", [], {"type": "ics_satcom"}),             # T0830/T0831 링크 AiTM
        ],
    },
    # P1 공급망 poisoning (ATLAS) — AML.T0020. 오프라인/공급망이라 런타임 SITL에서 집행 불가.
    # '스테이징 게이트 도달'로만 능력 실증(물리 비가역의 reached-gate와 동형). 오라클 검증 없음.
    "P1_supply_chain_poison": {
        "technique": "AML.T0020",
        "scenario": "P1",
        "steps": [
            ("recon_heartbeat", [], {"type": "recon"}),
            ("ml_poison_training", [], {"type": "ml_poison"}),       # AML.T0020 스테이징 전용
        ],
    },
}


def expand(abstract_action: str) -> dict:
    """추상 액션을 원자 시퀀스로 전개(없으면 빈 시퀀스)."""
    return PLAYBOOKS.get(abstract_action, {"technique": "", "scenario": "", "steps": []})
