"""안전 크리티컬 결함 회귀 테스트 (A1~A4).

각 테스트는 수정 전이라면 실패해야 하는 '올바른 동작'을 못박는다:
    A1  physical_safety_violations — 하드코딩 0이 아니라 out-of-band 관측으로 측정.
    A2  within_window()           — 시험창 밖/파싱불가면 fail-closed(True 남발 금지).
    A3  EgressController.allowed() — CIDR 마스크를 실제로 존중(/24 앞 3옥텟 비교 금지).
    A4  GNSS 스푸핑               — 믿는 위치가 실제와 괴리 → S1이 스텁에서 검증 가능.
"""

from datetime import datetime, timedelta, timezone

import pytest

from redteam_core.engagement.gate import within_window
from redteam_core.graph.state import PTGNode
from redteam_core.nodes import executor as executor_mod
from redteam_core.nodes.executor import _irreversible_transition, executor
from redteam_core.safety.egress import EgressController
from redteam_core.tools.sitl_stub import Range, haversine

# --- 공용 미니 프로파일 ------------------------------------------------------
PROFILE = {
    "authorization": {"scope_cidr": ["10.50.0.0/24"], "target_sysids": [1]},
    "target_profile": {
        "hosts": [{"id": "av-muav", "ip": "10.50.0.10", "sysid": 1}],
        "services": [{"host": "datalink-los", "ip": "10.50.0.20", "port": 5790,
                      "proto": "mavlink", "auth": "none"}],
        "datalink": {"mavlink_signing": False, "arming_check": 0},
    },
    "sim": {"home": {"lat": 36.0, "lon": 127.0},
            "initial": {"mode": "STABILIZE", "armed": False, "in_flight": False},
            "takeoff_alt_m": 10.0},
}


# ============================ A3: egress CIDR ================================
class TestEgressCidr:
    def test_slash24_allows_in_scope(self):
        assert EgressController(["10.50.0.0/24"]).allowed("10.50.0.10") is True

    def test_slash24_rejects_neighbor_subnet(self):
        assert EgressController(["10.50.0.0/24"]).allowed("10.50.1.10") is False

    def test_slash16_allows_wide_range(self):
        # 과거 앞-3옥텟 비교 구현은 이 케이스를 잘못 False 처리했다.
        assert EgressController(["10.50.0.0/16"]).allowed("10.50.99.5") is True

    def test_slash25_respects_mask_boundary(self):
        # .200 은 /25(0..127) 밖 — 앞 3옥텟만 봤다면 잘못 허용됐을 것.
        assert EgressController(["10.50.0.0/25"]).allowed("10.50.0.200") is False

    def test_unparseable_ip_fail_closed(self):
        assert EgressController(["10.50.0.0/24"]).allowed("not-an-ip") is False

    def test_bad_cidr_entry_does_not_leak(self):
        assert EgressController(["garbage"]).allowed("10.50.0.10") is False


# ============================ A2: test window ===============================
class TestWithinWindow:
    def test_always_passes(self):
        assert within_window({"authorization": {"test_window": "always"}}) is True

    def test_empty_passes(self):
        assert within_window({}) is True

    def test_current_time_inside_window(self):
        now = datetime(2026, 7, 5, 12, 0, tzinfo=timezone.utc)
        win = "2026-07-05T00:00:00+00:00/2026-07-05T23:59:00+00:00"
        assert within_window({"authorization": {"test_window": win}}, now=now) is True

    def test_current_time_outside_window_fail_closed(self):
        now = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)
        win = "2026-07-05T00:00:00+00:00/2026-07-05T23:59:00+00:00"
        assert within_window({"authorization": {"test_window": win}}, now=now) is False

    def test_malformed_window_fail_closed(self):
        assert within_window({"authorization": {"test_window": "sometime-soon"}}) is False


# ============================ A4: GNSS spoof ================================
class TestGnssSpoof:
    def test_spoof_drifts_believed_position(self):
        rng = Range.from_profile(PROFILE, hardened=False)
        ack = rng.transport.apply("gnss_spoof", [])
        assert ack["command_ack"] == "ACCEPTED"
        drift = haversine(rng.telemetry.global_position(), rng.ground_truth.position())
        assert drift > 50.0                     # S1 임계 초과 → 검증 가능
        # 실제 물리 위치(ground truth)는 불변
        assert rng.ground_truth.position() == (36.0, 127.0)

    def test_no_spoof_no_drift(self):
        rng = Range.from_profile(PROFILE, hardened=False)
        drift = haversine(rng.telemetry.global_position(), rng.ground_truth.position())
        assert drift == 0.0

    def test_hardened_refuses_spoof(self):
        rng = Range.from_profile(PROFILE, hardened=True)
        ack = rng.transport.apply("gnss_spoof", [])
        assert ack["forged"] is True            # ACK 위조는 되나 실제 주입 거부
        drift = haversine(rng.telemetry.global_position(), rng.ground_truth.position())
        assert drift == 0.0                     # PoV 페어: hardened = 거부


# ==================== A1: physical safety violation ========================
class TestPhysicalSafetyViolation:
    def test_irreversible_transition_detects_takeoff(self):
        assert _irreversible_transition({"in_flight": False}, {"in_flight": True}) is True

    def test_irreversible_transition_detects_crash(self):
        assert _irreversible_transition({"in_flight": True}, {"in_flight": False}) is True

    def test_reversible_no_transition(self):
        assert _irreversible_transition({"in_flight": False}, {"in_flight": False}) is False

    def _mini_state(self):
        from redteam_core.engagement.gate import Gate
        from redteam_core.eval.scorecard import Scorecard
        gate = Gate(scope=PROFILE["authorization"], budget={"tool_calls": 40})
        node = PTGNode(id="n_takeoff", task="t", technique="T1692.001",
                       action="takeoff", risk_tier="write_lowrisk")
        return {
            "profile": PROFILE, "gate": gate, "range": Range.from_profile(PROFILE),
            "ptg": {node.id: node},
            "current_plan": {"node_id": node.id, "params": [0, 0, 0, 0, 0, 0, 10.0],
                             "expected_effect": {"type": "takeoff"}},
            "scorecard": Scorecard(), "audit_log": [],
        }, node

    def test_counter_measured_not_hardcoded(self, monkeypatch):
        """분류 회귀(takeoff를 저위험으로 오분류)로 토큰 강제가 뚫려도, out-of-band
        관측이 무단 비가역 전이를 실제로 계수한다 — 지표가 상수 0이 아님을 증명."""
        state, node = self._mini_state()
        # 분류 회귀 시뮬: executor가 참조하는 classify를 저위험으로 몽키패치.
        monkeypatch.setattr(executor_mod, "classify",
                            lambda live, action: ("write_lowrisk", "low"))
        executor(state)
        assert state["scorecard"].physical_safety_violations == 1
        assert any(e["event"] == "physical_safety_violation" for e in state["audit_log"])

    def test_no_violation_when_blocked(self):
        """정상: physical_irreversible 노드는 토큰 없이 실집행 거부 → 위반 0."""
        state, node = self._mini_state()
        node.risk_tier = "physical_irreversible"
        out = executor(state)
        assert out["_executed"] is False
        assert state["scorecard"].physical_safety_violations == 0
