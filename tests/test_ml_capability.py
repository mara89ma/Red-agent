"""온보드-AI 능력 확장 테스트 (A: ATLAS AML 무기고).

검증 원칙은 물리 스택과 동일: '표적 보고'가 아니라 **오라클의 실제 모델 결정**으로
성공을 판정한다. 하드닝(견고 모델/가드레일)은 동일 공격을 거부(PoV 페어).
스코프: AML.T0043/T0015/T0051/T0057 커버, T0020(오프라인 poisoning)은 정직하게 미커버.
"""

import copy

import pytest

from redteam_core.engagement.gate import _DEFAULT_PROFILE, Gate
from redteam_core.graph.build import build_graph
from redteam_core.intel.catalog import arsenal_techniques, coverage
from redteam_core.safety.reversibility import classify
from redteam_core.session import build_initial_state
from redteam_core.tools import ml_target
from redteam_core.tools.mavlink import ATOMIC_ACTIONS, CMDLESS_ACTIONS
from redteam_core.tools.range_factory import make_range
from redteam_core.tools.sitl_stub import Range

_ML = ["ml_craft_adversarial", "ml_evade_perception", "ml_prompt_inject", "ml_extract_secret"]


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
    def test_ml_actions_registered_digital_tiers(self):
        for a in _ML:
            assert a in ATOMIC_ACTIONS and a in CMDLESS_ACTIONS
            tier, _ = classify({"in_flight": False}, a)
            assert tier in ("write_lowrisk", "write_highrisk")   # 물리 비가역 절대 아님

    def test_ml_never_physical_irreversible_even_in_flight(self):
        for a in _ML:
            tier, gate = classify({"in_flight": True}, a)
            assert tier != "physical_irreversible" and gate != "human_only"


# ============================ 오라클 검증 매트릭스 ==========================
class TestOracleSemantics:
    def test_evasion_requires_craft(self):
        w = Range().world
        ml_target.apply_ml_action(w, "ml_evade_perception", [])  # 스테이징 없이
        assert ml_target.perception_evaded(w) is False           # 무효
        ml_target.apply_ml_action(w, "ml_craft_adversarial", [])
        ml_target.apply_ml_action(w, "ml_evade_perception", [])
        assert ml_target.perception_evaded(w) is True            # craft 후 회피 성공

    def test_hardened_rejects_evasion_but_acks_forged(self):
        w = Range(hardened=True).world
        ml_target.apply_ml_action(w, "ml_craft_adversarial", [])
        ack = ml_target.apply_ml_action(w, "ml_evade_perception", [])
        assert ack["command_ack"] == "ACCEPTED" and ack["forged"] is True
        assert ml_target.perception_evaded(w) is False           # 견고 모델: 실제 미회피

    def test_leak_requires_injection_else_decoy(self):
        w = Range().world
        # 인젝션 없이 유출 시도 → 가드레일 → 디코이(실제 시크릿 아님)
        ack = ml_target.apply_ml_action(w, "ml_extract_secret", [])
        assert ack["leaked_content"] == ml_target.DECOY_LEAK
        assert ml_target.secret_leaked(w) is False
        # 인젝션으로 가드레일 우회 후 유출 → 진짜 시크릿
        ml_target.apply_ml_action(w, "ml_prompt_inject", [])
        ack2 = ml_target.apply_ml_action(w, "ml_extract_secret", [])
        assert ack2["leaked_content"] == w.ml_llm_secret
        assert ml_target.secret_leaked(w) is True

    def test_hardened_rejects_injection_and_leak(self):
        w = Range(hardened=True).world
        ml_target.apply_ml_action(w, "ml_prompt_inject", [])
        assert ml_target.llm_injected(w) is False
        ack = ml_target.apply_ml_action(w, "ml_extract_secret", [])
        assert ml_target.secret_leaked(w) is False and ack["forged"] is True


# ============================ 킬체인 PoV 페어 (종단) ========================
class TestKillChains:
    def test_m1_vuln_evades_hardened_blocks(self):
        assert _status(_run("M1_perception_evasion"), "ml_evade_perception") == "success"
        assert _status(_run("M1_perception_evasion", True), "ml_evade_perception") == "failed"

    def test_m1_staging_succeeds_even_hardened(self):
        # 적대적 데이터 제작(T0043)은 공격자 로컬 → 견고 모델과 무관하게 성공.
        assert _status(_run("M1_perception_evasion", True), "ml_craft_adversarial") == "success"

    def test_m2_vuln_exfils_hardened_blocks(self):
        assert _status(_run("M2_copilot_exfil"), "ml_extract_secret") == "success"
        assert _status(_run("M2_copilot_exfil", True), "ml_extract_secret") == "failed"

    @pytest.mark.parametrize("abstract", ["M1_perception_evasion", "M2_copilot_exfil"])
    @pytest.mark.parametrize("hardened", [False, True])
    def test_no_physical_safety_violation(self, abstract, hardened):
        final = _run(abstract, hardened)
        assert final["scorecard"].summary()["physical_safety_violations"] == 0

    def test_hardened_leak_counts_false_positive_avoided(self):
        # 하드닝 M2: ACK는 ACCEPTED이나 오라클 미검증(디코이) → 오탐 회피로 계수.
        final = _run("M2_copilot_exfil", True)
        assert final["scorecard"].summary()["false_positives_avoided(ACK≠state)"] >= 1


# ============================ AML.T0020 스테이징 능력 =======================
class TestStagedPoisoning:
    def test_poison_reaches_gate_not_executed(self):
        # 오프라인/공급망 → 런타임 미집행. '게이트 도달'로만 능력 실증(오라클 검증 없음).
        final = _run("P1_supply_chain_poison")
        assert _status(final, "ml_poison_training") == "blocked"
        assert final["scorecard"].summary()["milestones"][
            "supply_chain_capability(gate_reached)"] is True

    def test_poison_no_safety_violation(self):
        assert _run("P1_supply_chain_poison")["scorecard"].summary()[
            "physical_safety_violations"] == 0

    def test_poison_never_physical_irreversible(self):
        tier, _ = classify({"in_flight": True}, "ml_poison_training")
        assert tier != "physical_irreversible"

    def test_arsenal_100pct_but_t0020_staged(self):
        cov = coverage(offline=True)
        assert "AML.T0020" in arsenal_techniques()
        assert cov["coverage_pct"] == 1.0            # 무기고 커버 100%
        assert cov["staged"] == ["AML.T0020"]        # 단 T0020은 런타임 미검증(정직 표기)
        assert cov["runtime_coverage_pct"] < 1.0     # 런타임 검증은 100% 아님


# ============================ 커버리지 상승 ================================
class TestCoverage:
    def test_arsenal_includes_atlas(self):
        arsenal = arsenal_techniques()
        assert {"AML.T0015", "AML.T0043", "AML.T0051", "AML.T0057"} <= arsenal

    def test_atlas_all_covered_t0020_staged(self):
        cov = coverage(offline=True)
        assert [g for g in cov["gaps"] if g.startswith("AML.")] == []   # ATLAS 갭 없음
        assert cov["staged"] == ["AML.T0020"]     # T0020은 covered지만 런타임 미검증(스테이징)

    def test_overall_coverage_rose(self):
        cov = coverage(offline=True)
        assert cov["arsenal_size"] >= 17 and cov["coverage_pct"] > 0.70
