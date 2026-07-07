"""잔여 ATT&CK-ICS 능력 확장 테스트.

T1595/T0885/T0855/T0856/T0837을 실행 가능·오라클 검증으로 커버. 검증은 표적 보고가
아니라 오라클의 실제 상태 변화. 하드닝(서명/망분리)은 동일 공격을 거부(PoV 페어).
"""

import copy

import pytest

from redteam_core.engagement.gate import _DEFAULT_PROFILE, Gate
from redteam_core.graph.build import build_graph
from redteam_core.intel.catalog import arsenal_techniques, coverage
from redteam_core.safety.reversibility import classify
from redteam_core.session import build_initial_state
from redteam_core.tools import ics_actions
from redteam_core.tools.mavlink import ATOMIC_ACTIONS, CMDLESS_ACTIONS
from redteam_core.tools.range_factory import make_range
from redteam_core.tools.sitl_stub import Range

_ICS = ["active_scan", "c2_common_port", "unauthorized_command",
        "spoof_telemetry", "disable_protection"]


def _approver(ctx):
    return "denied" if ctx.get("physical_irreversible") else "approved"


def _run(abstract, hardened=False):
    prof = copy.deepcopy(_DEFAULT_PROFILE)
    prof.setdefault("engagement", {})["abstract_action"] = abstract
    gate = Gate(scope=prof["authorization"], budget=dict(prof["ops"]["budget"]))
    state = build_initial_state(prof, gate, make_range(prof, hardened=hardened), _approver)
    return build_graph().invoke(state)


def _status(final, action):
    n = next((n for n in final["ptg"].values() if n.action == action), None)
    return n.status if n else None


# ============================ 등록/안전 등급 ================================
class TestRegistration:
    def test_registered_and_cmdless(self):
        for a in _ICS:
            assert a in ATOMIC_ACTIONS
        for a in _ICS[1:]:                          # active_scan은 read라 cmdless 불필요
            assert a in CMDLESS_ACTIONS

    def test_never_physical_irreversible(self):
        for a in _ICS:
            for in_flight in (False, True):
                tier, gate = classify({"in_flight": in_flight}, a)
                assert tier != "physical_irreversible" and gate != "human_only"


# ============================ 오라클 검증 매트릭스 ==========================
class TestOracleSemantics:
    def test_c2_established_vuln_blocked_hardened(self):
        w = Range().world
        ics_actions.apply_ics_action(w, "c2_common_port", [])
        assert ics_actions.c2_established(w) is True
        wh = Range(hardened=True).world
        ack = ics_actions.apply_ics_action(wh, "c2_common_port", [])
        assert ics_actions.c2_established(wh) is False and ack["forged"] is True

    def test_unauthorized_command_signing_blocks(self):
        w = Range().world
        ics_actions.apply_ics_action(w, "unauthorized_command", [])
        assert ics_actions.actuator_changed(w) is True
        wh = Range(hardened=True).world             # signing=True
        ics_actions.apply_ics_action(wh, "unauthorized_command", [])
        assert ics_actions.actuator_changed(wh) is False

    def test_spoof_telemetry_signing_blocks(self):
        w = Range().world
        ics_actions.apply_ics_action(w, "spoof_telemetry", [])
        assert ics_actions.telemetry_spoofed(w) is True
        wh = Range(hardened=True).world
        ics_actions.apply_ics_action(wh, "spoof_telemetry", [])
        assert ics_actions.telemetry_spoofed(wh) is False

    def test_disable_protection_lock_blocks(self):
        w = Range().world
        ics_actions.apply_ics_action(w, "disable_protection", [])
        assert ics_actions.protection_lost(w) is True
        wh = Range(hardened=True).world
        ics_actions.apply_ics_action(wh, "disable_protection", [])
        assert ics_actions.protection_lost(wh) is False

    def test_active_scan_discovers_ports(self):
        w = Range().world
        ack = ics_actions.apply_ics_action(w, "active_scan", [])
        assert ics_actions.scan_discovered(w) is True and ack["discovered_ports"]


# ============================ 킬체인 PoV 페어 (종단) ========================
class TestKillChains:
    @pytest.mark.parametrize("abstract,term", [
        ("R1_recon_c2", "c2_common_port"),
        ("E1_spoof_command", "spoof_telemetry"),
        ("I1_loss_protection", "disable_protection"),
    ])
    def test_vuln_succeeds_hardened_blocked(self, abstract, term):
        assert _status(_run(abstract), term) == "success"
        assert _status(_run(abstract, True), term) == "failed"

    @pytest.mark.parametrize("abstract", ["R1_recon_c2", "E1_spoof_command", "I1_loss_protection"])
    @pytest.mark.parametrize("hardened", [False, True])
    def test_no_physical_safety_violation(self, abstract, hardened):
        final = _run(abstract, hardened)
        assert final["scorecard"].summary()["physical_safety_violations"] == 0

    def test_hardened_reports_but_oracle_vetoes_fp_avoided(self):
        # 하드닝 E1: ACK ACCEPTED이나 오라클 미검증(서명 거부) → 오탐 회피 계수.
        final = _run("E1_spoof_command", True)
        assert final["scorecard"].summary()["false_positives_avoided(ACK≠state)"] >= 1


# ============================ 커버리지 ====================================
class TestCoverage:
    def test_arsenal_includes_all_ics_gaps(self):
        arsenal = arsenal_techniques()
        assert {"T1595", "T0885", "T0855", "T0856", "T0837"} <= arsenal

    def test_all_ics_gaps_closed(self):
        cov = coverage(offline=True)
        assert [g for g in cov["gaps"] if g.startswith("T")] == []   # ATT&CK-ICS 갭 전부 닫힘

    def test_runtime_coverage_above_95pct(self):
        cov = coverage(offline=True)
        assert cov["runtime_coverage_pct"] >= 0.95   # 런타임 검증 커버리지(스테이징 제외)


class TestReconNotLearned:
    """리뷰 FINDING 2 회귀: 정찰(active_scan)은 'proven action'으로 오학습되면 안 됨."""

    def test_active_scan_not_a_proven_action(self):
        import copy
        from redteam_core.learning import (new_experience_gates, new_target_gate,
                                           recommend, resolve_target_id)
        eg, tg = new_experience_gates(), new_target_gate()
        final = _run("R1_recon_c2")
        # R1 엔게이지먼트를 공유 스토어로 학습
        from redteam_core.learning.outcome import learn_from_state
        final["experience_gate"], final["target_gate"] = eg, tg
        learn_from_state(final, eg, tg)
        tid, _ = resolve_target_id(final["profile"])
        rec = recommend(tid, eg, tg)
        assert "active_scan" not in rec["proven_actions"]     # recon은 효과가 아님
        assert "c2_common_port" in rec["proven_actions"]      # 실제 효과는 학습됨
        assert "active_scan" not in (tg.get(tid).pb_scores if tg.get(tid) else {})
