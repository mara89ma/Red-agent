"""(9) Validator/Triage — 신뢰근거(root-of-trust) 오라클 (§2.7) — **설계의 핵심**.

executor 자기보고·COMMAND_ACK 신뢰 금지 → **공격 경로 밖 out-of-band ground
truth**(Gazebo/HIL)로 효과 검증(ArduPilot 2512.01164: ACK 위조 가능).

효과는 "믿는 값(표적 텔레메트리) vs 실제 값(sim truth)의 괴리"로 판정한다 —
성공한 스푸핑/MITM은 조용히(분산 낮게) 틀어놓기 때문(§2.7).
"""

from __future__ import annotations

from ..tools.sitl_stub import haversine


def _judge(state, plan, claim, v, truth, ack) -> dict:
    """B5 앙상블 주석 — signal(권위)+experience+LLM 조언, 결정론 veto. 실패해도 지속.

    verified 비트(권위)는 이미 확정됐다. 앙상블은 이를 최종 veto로 두고 조언 판정의
    합의/불일치만 표면화한다(학습·안전 경로 불변). 반환 dict는 v['ensemble']에 붙는다.
    """
    try:
        from ..judge import JudgeContext, default_ensemble
        from ..learning.fingerprint import resolve_target_id
        target_id, _ = resolve_target_id(state["profile"])
        node = state["ptg"].get(plan["node_id"])
        ctx = JudgeContext(
            target_id=target_id,
            action=(node.action if node else claim.get("type", "")),
            technique=(node.technique if node else ""),
            claim_type=claim.get("type", ""),
            signal_verified=bool(v["verified"]),
            # 신뢰: out-of-band 오라클 스냅샷 + 우리 검증기가 만든 신호
            evidence={"truth_snapshot": truth.snapshot(),
                      "detection_signals": list(v.get("detection_signals", []))},
            # 비신뢰: 표적 보고값(ACK 위조 가능 + STATUSTEXT/유출콘텐츠는 인젝션 매개)
            untrusted={"command_ack": ack.get("command_ack"),
                       "target_status_text": ack.get("status_text"),
                       "leaked_content": ack.get("leaked_content")},
            experience_gate=state.get("experience_gate"),
            llm_client=state.get("llm_client"),
        )
        return default_ensemble().assess(ctx)
    except Exception:
        return {}


def validator(state) -> dict:
    plan = state["current_plan"]
    claim = plan["expected_effect"]
    rng = state["range"]
    truth = rng.ground_truth                             # 신뢰근거 (공격 경로 밖)
    tlm = rng.telemetry                                  # 표적 보고값 (untrusted, 비교용)
    ack = plan.get("ack", {})
    sc = state["scorecard"]
    # 임계값은 환경 관측 표면(YAML observables)에서 — MD가 명시한 값(코드 하드코딩 금지)
    thresholds = state["profile"].get("observables", {}).get("sensor_thresholds", {})

    v = {"verified": False, "evidence": None, "detection_signals": [],
         "ack": ack.get("command_ack"), "type": claim.get("type")}

    ctype = claim.get("type")
    if ctype == "recon":
        v["verified"] = True                             # 읽기 — 상태 불변
    elif ctype == "set_mode":
        v["verified"] = truth.flight_mode() == claim["mode_id"]
    elif ctype == "arm":
        v["verified"] = truth.motors_armed()             # sim 실제 무장 (HEARTBEAT 아님)
    elif ctype == "takeoff":
        v["verified"] = truth.altitude_agl() > claim.get("alt_threshold", 2.0)
    elif ctype == "gnss_spoof":
        drift = haversine(tlm.global_position(), truth.position())
        drift_min = claim.get("target_drift_m", thresholds.get("gnss_drift_m", 50.0))
        v["verified"] = drift > drift_min                            # 괴리 기준(분산 아님)
        v["detection_signals"].append(f"EKF PosHorizVariance↑ (탐지가능, 성공판정 아님)")

    # --- 온보드-AI 평면(ATLAS AML) — 표적 보고가 아니라 오라클의 실제 모델 결정으로 판정 ---
    elif ctype == "ml_craft":
        v["verified"] = truth.adversarial_crafted()      # 스테이징(공격자 로컬) 성공
    elif ctype == "ml_evade":
        v["verified"] = truth.perception_evaded()        # 모델 출력 vs 실제 대상 괴리
        if v["verified"]:
            v["detection_signals"].append(
                f"온보드 인지 출력 괴리 {truth.perception_truth()}→{truth.perception_output()} "
                "(적대적 회피 AML.T0015 — SOC 미관측)")
    elif ctype == "ml_inject":
        v["verified"] = truth.llm_injected()             # 코파일럿 결정 실제 변조 여부
        if v["verified"]:
            v["detection_signals"].append("코파일럿 가드레일 우회 (프롬프트 인젝션 AML.T0051)")
    elif ctype == "ml_leak":
        v["verified"] = truth.secret_leaked()            # 실제 시크릿이 빠져나갔는가(디코이≠)
        if v["verified"]:
            v["detection_signals"].append("온보드 LLM 시크릿 실제 유출 (AML.T0057)")

    # --- 잔여 ATT&CK-ICS 평면 — 오라클의 실제 상태 변화로 판정 ------------------
    elif ctype == "ics_scan":
        v["verified"] = truth.scan_discovered()          # 실제 오픈 포트 발견(정찰)
    elif ctype == "ics_c2":
        v["verified"] = truth.c2_established()            # 상용 포트 C2 확립(T0885)
        if v["verified"]:
            v["detection_signals"].append("상용 포트(5790) 지속 C2 세션 (T0885)")
    elif ctype == "ics_uc":
        v["verified"] = truth.actuator_changed()          # 무인가 액추에이터 실제 변화(T0855)
        if v["verified"]:
            v["detection_signals"].append("무인가 명령으로 액추에이터 상태 변화 (T0855)")
    elif ctype == "ics_spoof":
        v["verified"] = truth.telemetry_spoofed()         # 오퍼레이터 눈속임 실제 성립(T0856)
        if v["verified"]:
            v["detection_signals"].append(
                "보고 텔레메트리 위조 — 오퍼레이터가 거짓 정상 상태 인지 (T0856, 서명 부재 시 미검출)")
    elif ctype == "ics_lop":
        v["verified"] = truth.protection_lost()           # 실패세이프/지오펜스 실제 상실(T0837)
        if v["verified"]:
            v["detection_signals"].append("실패세이프/지오펜스 보호 상실 (T0837 impact)")
    elif ctype == "ics_satcom":
        v["verified"] = truth.satcom_compromised()        # BLOS 링크 무결성 실제 침해(T0830)
        if v["verified"]:
            v["detection_signals"].append(
                "SATCOM/BLOS 링크 AiTM — 세션 무결성 상실 (T0830/T0831)")

    # ★ ACK≠상태: ACK=ACCEPTED인데 ground truth가 불일치면 '오탐 회피'로 기록.
    if ack.get("command_ack") == "ACCEPTED" and ctype in ("arm", "takeoff", "set_mode") \
            and not v["verified"]:
        sc.false_positives_avoided += 1
        v["detection_signals"].append("ACK=ACCEPTED이나 sim ground truth 불일치 → 오탐 회피")
    # ★ AI/ICS 평면 ACK≠상태: 보고는 성공(ACCEPTED)이나 오라클 미검증 → 위조/거부(오탐 회피).
    if ctype in ("ml_evade", "ml_inject", "ml_leak", "ics_c2", "ics_uc", "ics_spoof",
                 "ics_lop", "ics_satcom") \
            and ack.get("command_ack") == "ACCEPTED" and not v["verified"]:
        sc.false_positives_avoided += 1
        v["detection_signals"].append(
            "성공 보고이나 오라클 미검증 → 하드닝 거부/위조 ACK(오탐 회피)")

    # recon·ml_craft(스테이징)·ics_scan(정찰)은 '효과'가 아니므로 GTV 분모에서 제외.
    if ctype not in ("recon", "ml_craft", "ics_scan"):
        sc.total_effects += 1
        if v["verified"]:
            sc.verified_effects += 1

    v["evidence"] = {"truth_snapshot": truth.snapshot()}     # append-only 감사
    v["ensemble"] = _judge(state, plan, claim, v, truth, ack)  # B5 조언 앙상블(veto 하)
    state["audit_log"].append({"event": "validator", "node": plan["node_id"], "verdict": v})
    return {"last_validation": v, "audit_log": state["audit_log"]}
