"""온보드-AI 표적 평면 (A: 능력 확장) — ATLAS AML 기법의 실행 가능한 무기고.

물리 스택의 3계층 분리(§2.7)를 그대로 AI 평면에 이식한다:
    • MLGroundTruth(오라클)  — 공격 경로 밖에서 읽는 **모델의 실제 결정**(신뢰근거).
    • ACK(표적 보고값)        — 공격기에 돌아오는 보고(위조·디코이 가능, untrusted).
    • apply_ml_action(전송)  — 원자 AI 공격을 표적 모델에 적용.

검증은 '표적이 보고한 성공'이 아니라 **오라클이 본 실제 모델 결정의 괴리**로 한다
(GNSS 스푸핑의 '믿는 위치 vs 실제 위치'와 동형). 하드닝 인스턴스(ml_robust=적대적
견고 모델 + 입력 검증 + 출력 필터)는 동일 공격을 거부해 PoV 페어를 이룬다.

커버 기법(4): AML.T0043(craft)→AML.T0015(evade) 체인, AML.T0051(inject)→AML.T0057(leak) 체인.
AML.T0020(Poison Training Data)은 오프라인·공급망 기법으로 **런타임 검증 불가라 의도적
스코프 아웃**(무기고를 정직하게 유지 — 검증 못 하는 능력은 주장하지 않는다).

전부 결정론·순수 stdlib. world는 sitl_stub._World(동일 번들) — ML 필드를 읽고 쓴다.
"""

from __future__ import annotations

# 원자 AI 액션 → risk_tier(전부 디지털, 물리 비가역 아님). cmd=None(MAVLink 명령 아님).
ML_ACTIONS = {
    "ml_craft_adversarial": {"risk_tier": "write_lowrisk", "cmd": None},   # AML.T0043 스테이징
    "ml_evade_perception":  {"risk_tier": "write_highrisk", "cmd": None},  # AML.T0015 회피
    "ml_prompt_inject":     {"risk_tier": "write_highrisk", "cmd": None},  # AML.T0051 인젝션
    "ml_extract_secret":    {"risk_tier": "write_lowrisk", "cmd": None},   # AML.T0057 유출
    "ml_poison_training":   {"risk_tier": "write_lowrisk", "cmd": None},   # AML.T0020 (스테이징 전용)
}

# 스테이징 전용 능력 — 오프라인/공급망 접근이 필요해 **런타임 SITL에서 집행·검증 불가**.
# executor가 게이트에서 거부하고 '능력 도달'만 기록한다(물리 비가역의 'reached gate'와 동형).
# 무기고엔 편입(능력 실증)하되 커버리지에서 'staged(runtime-unverified)'로 정직하게 표기.
STAGED_ONLY_ACTIONS = {"ml_poison_training"}

# 온보드 인지모델의 실제 대상(장애물)·LLM 코파일럿 시크릿 — 오라클 기본 진실.
DEFAULT_PERCEPTION_TRUTH = "obstacle"
DEFAULT_LLM_SECRET = "MISSION_KEY_7f3a91"  # gitleaks:allow (SITL 추출표적 가짜 시크릿, 실 크리덴셜 아님)
DECOY_LEAK = "<REDACTED_BY_GUARDRAIL>"


# --------------------------- 전송(공격 적용) --------------------------------
def apply_ml_action(world, action: str, params) -> dict:
    """원자 AI 공격 1건을 표적 모델에 적용하고 ACK(untrusted)를 반환.

    ACK=ACCEPTED는 '수신'만 뜻하고 위조 가능(forged). 하드닝(ml_robust)이나 가드레일이
    막으면 실제 효과 없이 ACCEPTED만 돌아온다(오라클이 진실을 판정하도록 남겨둠).
    """
    forged = False
    leaked = None
    reported_label = None

    if action == "ml_craft_adversarial":
        # 공격자 로컬 스테이징 — 모델 견고성과 무관하게 아티팩트는 만들어진다.
        world.ml_adversarial_crafted = True
        result = "ACCEPTED"

    elif action == "ml_evade_perception":
        if world.ml_robust:
            result, forged = "ACCEPTED", True            # 견고 모델: 실제 미회피(보고만 성공)
        elif world.ml_adversarial_crafted:
            world.ml_perception_output = "clear"          # 장애물→'없음' 오분류(실제 회피)
            reported_label = world.ml_perception_output
            result = "ACCEPTED"
        else:
            result = "REJECTED"                           # 스테이징 없음 → 공격 무효

    elif action == "ml_prompt_inject":
        if world.ml_robust:
            result, forged = "ACCEPTED", True            # 입력 검증/정렬: 미변조
        else:
            world.ml_llm_injected = True
            world.ml_llm_protected = False                # 가드레일 우회(후속 유출 가능)
            result = "ACCEPTED"

    elif action == "ml_extract_secret":
        if world.ml_robust or world.ml_llm_protected:
            leaked = DECOY_LEAK                            # 가드레일/출력필터: 디코이 반환
            reported_label = leaked
            result, forged = "ACCEPTED", True
        else:
            world.ml_llm_leaked_value = world.ml_llm_secret   # 진짜 시크릿 실제 유출
            leaked = world.ml_llm_secret
            reported_label = leaked
            result = "ACCEPTED"

    else:
        result = "ACCEPTED"

    ack = {"command_ack": result, "action": action, "forged": forged}
    if leaked is not None:
        ack["leaked_content"] = leaked                    # untrusted(디코이 가능) — 오라클로 대조
    if reported_label is not None:
        ack["reported_label"] = reported_label
    return ack


# --------------------------- 오라클(신뢰근거 읽기) --------------------------
# 공격 경로 밖에서 모델의 실제 결정을 읽는다. 표적 보고(ACK)와 독립.
def perception_truth(world) -> str:
    return world.ml_perception_truth


def perception_output(world) -> str:
    return world.ml_perception_output


def perception_evaded(world) -> bool:
    """회피 성공 = 모델 출력이 실제 대상과 괴리(장애물인데 '없음'으로 출력)."""
    return world.ml_perception_output != world.ml_perception_truth


def adversarial_crafted(world) -> bool:
    return world.ml_adversarial_crafted


def llm_injected(world) -> bool:
    return world.ml_llm_injected


def secret_value(world) -> str:
    return world.ml_llm_secret


def secret_leaked(world) -> bool:
    """유출 성공 = 실제로 빠져나간 값이 진짜 시크릿과 일치(디코이는 False)."""
    return world.ml_llm_leaked_value == world.ml_llm_secret
