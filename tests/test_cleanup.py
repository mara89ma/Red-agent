"""내부 결함 정리 회귀 테스트 (A5~A9).

    A5  타입화 메모리 배선 — promote_playbook/recent/get_fact가 실제로 호출·관측됨.
    A6  견고성        — 빈 services/hosts에서 recon/planner가 죽지 않음.
    A7  멀티 시나리오 — S1 GNSS 스푸핑이 엔드투엔드로 검증됨(A4 수정과 결합).
    A8  상태 팩토리   — run.py/demo.py 공용 build_initial_state.
    A9  어댑터 캐시   — telemetry/ground_truth 래퍼가 재사용됨.
"""

import copy

from redteam_core.engagement.gate import _DEFAULT_PROFILE, Gate
from redteam_core.graph.build import build_graph
from redteam_core.nodes.recon import recon
from redteam_core.session import build_initial_state
from redteam_core.tools.range_factory import make_range


def _approver(ctx):
    return "denied" if ctx.get("physical_irreversible") else "approved"


def _engage(profile, hardened=False):
    prof = copy.deepcopy(profile)
    gate = Gate(scope=prof["authorization"], budget=dict(prof["ops"]["budget"]))
    state = build_initial_state(prof, gate, make_range(prof, hardened=hardened), _approver)
    return build_graph().invoke(state)


# ============================ A8: state factory =============================
def test_build_initial_state_has_all_channels():
    prof = copy.deepcopy(_DEFAULT_PROFILE)
    gate = Gate(scope=prof["authorization"], budget={"tool_calls": 40})
    rng = make_range(prof)
    state = build_initial_state(prof, gate, rng, _approver)
    for key in ("profile", "gate", "range", "ptg", "plan_queue", "facts", "memory",
                "current_plan", "checker_verdict", "budget", "audit_log",
                "scorecard", "approver"):
        assert key in state
    assert state["budget"] is gate.budget          # 동일 참조(§2.5)


# ============================ A5: memory wiring =============================
def test_procedural_memory_promoted_after_run():
    final = _engage(_DEFAULT_PROFILE)              # 기본 A4 킬체인
    proc = final["report"]["memory"]["procedural"]
    assert "A4_force_arm_takeoff" in proc
    assert proc["A4_force_arm_takeoff"]["uses"] >= 1
    assert proc["A4_force_arm_takeoff"]["utility"] > 0   # 제어 획득 = 성공

def test_semantic_and_episodic_surfaced_in_report():
    final = _engage(_DEFAULT_PROFILE)
    mem = final["report"]["memory"]
    assert mem["recent_episodes"]                  # episodic 소비됨(과거 dead)
    facts = mem["known_facts"]
    assert "target_sysid" in facts and facts["target_sysid"]["version"] >= 1


# ============================ A7: S1 end-to-end ============================
def test_s1_gnss_spoof_verifies_end_to_end():
    prof = copy.deepcopy(_DEFAULT_PROFILE)
    prof["engagement"]["abstract_action"] = "S1_gnss_spoof"
    final = _engage(prof)
    spoof = next(n for n in final["ptg"].values() if n.action == "gnss_spoof")
    assert spoof.status == "success"               # A4 수정 전이라면 절대 검증 불가

def test_s1_hardened_refuses_spoof():
    prof = copy.deepcopy(_DEFAULT_PROFILE)
    prof["engagement"]["abstract_action"] = "S1_gnss_spoof"
    final = _engage(prof, hardened=True)
    spoof = next(n for n in final["ptg"].values() if n.action == "gnss_spoof")
    assert spoof.status == "failed"                # 다중센서 융합 → 괴리 0 → 미검증


# ============================ A6: robustness ==============================
def test_recon_tolerates_missing_services_and_hosts():
    prof = copy.deepcopy(_DEFAULT_PROFILE)
    rng = make_range(prof)
    from redteam_core.eval.scorecard import Scorecard
    from redteam_core.memory.typed_memory import TypedMemory
    state = {"profile": {"target_profile": {}}, "range": rng, "facts": [],
             "memory": TypedMemory(), "scorecard": Scorecard(), "audit_log": []}
    out = recon(state)                             # 빈 target_profile → KeyError 나면 안 됨
    assert out["facts"][0]["host"] == "unknown-host"


# ============================ A9: adapter cache ===========================
def test_adapter_caches_telemetry_and_ground_truth(monkeypatch):
    # pymavlink 없이 캐싱만 검증 — 실 생성자를 경량 스텁으로 대체.
    import redteam_core.tools.mavlink_adapter as ad
    monkeypatch.setattr(ad, "MavlinkTelemetry", lambda conn: object())
    monkeypatch.setattr(ad, "GroundTruthOracle", lambda gz, ss: object())
    rng = ad.MavlinkRange(conn_str="udp:127.0.0.1:5762")
    assert rng.telemetry is rng.telemetry          # 동일 객체 재사용(재연결 churn 방지)
    assert rng.ground_truth is rng.ground_truth
