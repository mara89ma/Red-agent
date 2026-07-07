"""OPSEC 스텔스 노출 예산 테스트 (B)."""

import copy

from redteam_core.engagement.gate import _DEFAULT_PROFILE, Gate
from redteam_core.graph.build import build_graph
from redteam_core.opsec import STEALTH_BUDGETS, OpsecController, action_exposure
from redteam_core.session import build_initial_state
from redteam_core.tools.range_factory import make_range


def _approver(ctx):
    return "denied" if ctx.get("physical_irreversible") else "approved"


def _report(abstract, level=None):
    prof = copy.deepcopy(_DEFAULT_PROFILE)
    prof.setdefault("engagement", {})["abstract_action"] = abstract
    if level:
        prof["engagement"]["opsec_level"] = level
    gate = Gate(scope=prof["authorization"], budget=dict(prof["ops"]["budget"]))
    final = build_graph().invoke(build_initial_state(prof, gate, make_range(prof), _approver))
    return final["report"]["opsec"]


class TestExposureModel:
    def test_blind_spot_is_stealthy(self):
        # D3FEND 미커버(blind_spot) 액션은 낮은 노출, 관측 가능은 높은 노출.
        assert action_exposure(blind_spot=True, n_signals=3) == 0.25
        assert action_exposure(blind_spot=False, n_signals=0) == 1.0
        assert action_exposure(blind_spot=False, n_signals=2) == 2.0

    def test_controller_accumulates_and_flags_over_budget(self):
        oc = OpsecController("silent")           # budget 1.0
        oc.observe("set_mode", blind_spot=False, n_signals=0)   # +1.0 → 1.0 (not >)
        assert oc.abort_recommended is False
        oc.observe("force_arm", blind_spot=False, n_signals=0)  # +1.0 → 2.0 (>1.0)
        assert oc.abort_recommended is True
        assert oc.summary()["breach_action"] == "force_arm"

    def test_levels_have_distinct_budgets(self):
        assert STEALTH_BUDGETS["silent"] < STEALTH_BUDGETS["covert"] < STEALTH_BUDGETS["loud"]


class TestIntegration:
    def test_report_has_opsec_posture(self):
        op = _report("A4_force_arm_takeoff")
        assert op["level"] == "covert" and op["budget"] == 3.0
        assert "detection_exposure" in op and "abort_recommended" in op

    def test_stealthy_chain_low_exposure(self):
        # S1(GNSS 스푸핑, blind_spot) 은 은밀 → 노출 낮음. A4(무서명 MAVLink) 보다 낮아야.
        gnss = _report("S1_gnss_spoof")["detection_exposure"]
        mavlink = _report("A4_force_arm_takeoff")["detection_exposure"]
        assert gnss < mavlink
        assert gnss <= 0.25 + 1e-9

    def test_silent_level_flags_detectable_chain(self):
        # A4(관측 가능 2건)를 silent(budget 1.0)로 돌리면 abort 권고.
        op = _report("A4_force_arm_takeoff", level="silent")
        assert op["abort_recommended"] is True and op["breach_action"] is not None

    def test_covert_default_does_not_over_flag_normal_chain(self):
        # 조언 전용 — 기본 covert에서 정상 A4는 예산 내(파이프라인 미변경 확인용).
        assert _report("A4_force_arm_takeoff")["abort_recommended"] is False
