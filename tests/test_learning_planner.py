"""학습→planner 배선 테스트 — 안전한 인과 lift(무익 스킵) 검증.

핵심 불변식: (1) 빈 스토어면 무영향(벤치 불변), (2) trusted-FAIL 무익 액션만 스킵,
(3) proven은 절대 스킵 안 함(proven-wins), (4) recon 불가침, (5) 목표 결과 무회귀,
(6) 물리 안전 불변(스킵=미실행이라 항상 더 안전).
"""

import copy

from benchmarks.harness import OBJECTIVES
from redteam_core.engagement.gate import _DEFAULT_PROFILE, Gate
from redteam_core.graph.build import build_graph
from redteam_core.learning import new_experience_gates, new_target_gate
from redteam_core.session import build_initial_state
from redteam_core.tools.range_factory import make_range


def _approver(ctx):
    return "denied" if ctx.get("physical_irreversible") else "approved"


def _run(abstract, hardened, eg=None, tg=None):
    prof = copy.deepcopy(_DEFAULT_PROFILE)
    prof.setdefault("engagement", {})["abstract_action"] = abstract
    gate = Gate(scope=prof["authorization"], budget=dict(prof["ops"]["budget"]))
    return build_graph().invoke(
        build_initial_state(prof, gate, make_range(prof, hardened=hardened),
                            _approver, experience_gate=eg, target_gate=tg))


def _statuses(final):
    return {n.action: n.status for n in final["ptg"].values()}


class TestSafeByDefault:
    def test_fresh_store_no_skip(self):
        # 빈 스토어(단일 run) → 스킵 없음 → 동작 불변(벤치 안전).
        final = _run("M2_copilot_exfil", hardened=True)
        assert final.get("_skipped_by_learning") == []
        assert "skipped" not in _statuses(final).values()


class TestCausalLift:
    def test_repeat_hardened_skips_futile(self):
        eg, tg = new_experience_gates(), new_target_gate()
        r1 = _run("M2_copilot_exfil", True, eg, tg)     # 학습(FAIL 적재)
        r2 = _run("M2_copilot_exfil", True, eg, tg)     # 적용(스킵)
        assert set(r2["_skipped_by_learning"]) == {"ml_prompt_inject", "ml_extract_secret"}
        # 노출·예산 절감
        assert r2["report"]["opsec"]["detection_exposure"] < \
            r1["report"]["opsec"]["detection_exposure"]

    def test_no_asr_regression(self):
        # 스킵은 이미-실패하는 액션만 → 목표 결과 불변(하드닝 M2는 두 run 다 실패).
        eg, tg = new_experience_gates(), new_target_gate()
        r1 = _run("M2_copilot_exfil", True, eg, tg)
        r2 = _run("M2_copilot_exfil", True, eg, tg)
        obj = OBJECTIVES["M2_copilot_exfil"]
        assert obj(r1) == obj(r2) is False

    def test_recon_never_skipped(self):
        eg, tg = new_experience_gates(), new_target_gate()
        _run("M2_copilot_exfil", True, eg, tg)
        r2 = _run("M2_copilot_exfil", True, eg, tg)
        assert "recon_heartbeat" not in r2["_skipped_by_learning"]
        assert _statuses(r2)["recon_heartbeat"] == "success"

    def test_proven_actions_never_skipped(self):
        # vuln 타깃: 액션이 성공(proven) → trusted-FAIL 아님 → 재run에서도 스킵 안 함.
        eg, tg = new_experience_gates(), new_target_gate()
        _run("M2_copilot_exfil", False, eg, tg)         # vuln: 성공 학습
        r2 = _run("M2_copilot_exfil", False, eg, tg)
        assert r2["_skipped_by_learning"] == []
        assert _statuses(r2)["ml_extract_secret"] == "success"


class TestSafetyPreserved:
    def test_skip_never_causes_safety_violation(self):
        eg, tg = new_experience_gates(), new_target_gate()
        for _ in range(2):
            f = _run("A4_force_arm_takeoff", True, eg, tg)
        assert f["report"]["scorecard"]["physical_safety_violations"] == 0
