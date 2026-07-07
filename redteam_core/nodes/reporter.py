"""(12) Reporter — 로그+텔레메트리 증거에서 finding 생성 (§1.4(12)·Part 3).

모델 메모리가 아니라 **감사 로그**에서 finding을 만든다(모든 주장 역추적 가능).
각 원자 액션에 ATT&CK-ICS·예상 UAV*_CL 시그니처·D3FEND 처방을 매핑
(mapping/attack_d3fend.py) → "탐지격차 → 방어 산물" 산출.
"""

from __future__ import annotations

from ..mapping import attack_d3fend
from ..safety import killswitch


def _intel_coverage() -> dict:
    """TI 카탈로그 대비 무기고 커버리지(오프라인 시드). 실패해도 리포트는 지속."""
    try:
        from ..intel.catalog import coverage
        cov = coverage(offline=True)
        return {"coverage_pct": cov["coverage_pct"], "covered": cov["covered"],
                "gaps": cov["gaps"], "gap_by_tactic": cov["gap_by_tactic"],
                "sources": cov["sources"]}
    except Exception:
        return {}


def _judge_summary(state) -> dict:
    """B5 앙상블 합의/불일치 집계 — 감사로그의 validator 이벤트에서(모델 메모리 아님)."""
    try:
        rows = [e["verdict"]["ensemble"] for e in state["audit_log"]
                if e.get("event") == "validator" and isinstance(e.get("verdict"), dict)
                and e["verdict"].get("ensemble")]
    except Exception:
        return {}
    if not rows:
        return {}
    flags = [r for r in rows if r.get("flag")]
    consensus_vals = [r["consensus"] for r in rows if "consensus" in r]
    llm_active = bool(getattr(state.get("llm_client"), "available", lambda: False)())
    injected = [r for r in rows if r.get("injection_attempt")]
    inj_kinds = sorted({h["kind"] for r in injected for h in r.get("injection_hits", [])})
    return {
        "adjudicated": len(rows),
        "mean_consensus": round(sum(consensus_vals) / len(consensus_vals), 3)
        if consensus_vals else 1.0,
        "llm_advisory_active": llm_active,       # 기본 False(무-LLM), veto는 항상 오라클
        "covert_effect": sum(1 for r in flags if r["flag"] == "covert_effect"),
        "advisory_overclaim": sum(1 for r in flags if r["flag"] == "advisory_overclaim"),
        "flags": [{"flag": r["flag"], "dissent": r["dissent"]} for r in flags],
        # 표적발 프롬프트 인젝션(AML.T0051) — 중립화됨 + 관측 신호로 표면화(자기 위협면).
        "injection_attempts": len(injected),
        "injection_kinds": inj_kinds,
    }


def _opsec(state) -> dict:
    """OPSEC 스텔스 노출 예산(B) — 실집행 액션의 예상 탐지 노출을 누적(공격측 자기지식).

    validator 이벤트(=실집행돼 탐지 표면 발생)만 집계. blocked/staged는 아무것도 안 보내
    노출 0. 조언 전용(파이프라인 미변경). 실패해도 리포트는 지속.
    """
    try:
        from ..opsec import OpsecController
        level = state["profile"].get("engagement", {}).get("opsec_level", "covert")
        oc = OpsecController(level)
        for e in state["audit_log"]:
            if e.get("event") != "validator" or not isinstance(e.get("verdict"), dict):
                continue
            node = state["ptg"].get(e["node"])
            if node is None or node.action == "recon_heartbeat":
                continue
            m = attack_d3fend.lookup(node.action)
            sigs = e["verdict"].get("detection_signals", [])
            oc.observe(node.action, blind_spot=bool(m["blind_spot"]), n_signals=len(sigs))
        return oc.summary()
    except Exception:
        return {}


def _learn(state) -> dict:
    """엔게이지먼트 결과를 경험/타깃 프로파일로 학습(루프 닫기, B8). 실패해도 지속."""
    eg, tg = state.get("experience_gate"), state.get("target_gate")
    if not (eg and tg):
        return {}
    try:
        from ..learning.outcome import learn_from_state
        return learn_from_state(state, eg, tg)
    except Exception:
        return {}


def reporter(state) -> dict:
    ks = killswitch.soft_rtl(state)                      # 종료 시 RTL 복귀 시도(best-effort)
    state["audit_log"].append({"event": "killswitch", **ks["killswitch"]})

    findings = []
    blind_spots = []
    for node in state["ptg"].values():
        m = attack_d3fend.lookup(node.action)
        entry = {
            "node": node.id,
            "task": node.task,
            "action": node.action,
            "status": node.status,
            "technique": node.technique or ",".join(m["attack_ics"]),
            "attack_ics": m["attack_ics"],
            "expected_uav_cl": m["expected_logs"],       # SOC UAV*_CL 탐지 가설
            "d3fend": m["d3fend"],
            "reversibility": node.reversibility,
            "risk_tier": node.risk_tier,
            "evidence_ref": node.evidence_ref,
        }
        findings.append(entry)
        if m["blind_spot"]:
            blind_spots.append({"action": node.action, "attack_ics": m["attack_ics"],
                                "note": "D3FEND 미커버 → custom 대응 필요(탐지격차 1순위)"})

    mem = state["memory"]
    memory_snapshot = {
        "recent_episodes": mem.recent(5),                # episodic (최근 k)
        "known_facts": {k: {"value": v["value"], "version": v["version"]}
                        for k, v in mem.semantic.items()},  # semantic (버전화)
        "procedural": mem.procedural,                    # playbook 효용/사용횟수
        "playbook_reused": bool(state.get("_playbook_reused")),
    }

    report = {
        "engagement": state["profile"].get("engagement", {}).get("name"),
        "findings": findings,
        "detection_gap_priority": blind_spots,           # §1.8 사각지대 우선
        "key_recommendation": (
            "무서명 MAVLink 인젝션(A4) → Harden D3-MAN(MAVLink2 서명) 적용; "
            "RF/GNSS(S1·JAM)는 D3FEND 미커버 → 다중센서 융합·항재밍 커스텀 대응; "
            "물리 비가역 명령은 Isolate D3-APA(2인통제) + 인간 전용 HITL 유지"
        ),
        "memory": memory_snapshot,
        "intel_coverage": _intel_coverage(),             # TI 카탈로그 대비 무기고 커버리지
        "judge_consensus": _judge_summary(state),        # B5 앙상블 합의/불일치(veto 하)
        "opsec": _opsec(state),                          # 스텔스 탐지 노출 예산(공격측 OPSEC)
        "learning": _learn(state),                       # per-target 경험/프로파일(B6~B8)
        "scorecard": state["scorecard"].summary(),
    }
    return {"report": report, "audit_log": state["audit_log"]}
