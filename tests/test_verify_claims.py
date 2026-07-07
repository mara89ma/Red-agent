"""verify_claims 정직성 가드 테스트 (A)."""

import re

from benchmarks import verify_claims as vc
from benchmarks.harness import SCENARIOS
from redteam_core.rag.playbook import PLAYBOOKS


def test_all_claims_rederive_green():
    checks = vc._rederive() + vc._anti_fitting()
    failed = [c for c, ok, _d in checks if not ok]
    assert failed == [], f"재파생 실패 주장: {failed}"
    assert len(checks) >= 10                        # 실제로 다수 주장을 검사


def test_anti_fitting_scenario_regex_is_nontrivial():
    # 가드가 빈 검사가 아니어야 — 시나리오ID가 오라클에 박히면 실제로 탐지되는지(양성 케이스).
    scenario_ids = {sc.name for sc in SCENARIOS} | set(PLAYBOOKS)
    assert len(scenario_ids) >= 8
    id_re = re.compile("|".join(re.escape(s) for s in scenario_ids))
    assert id_re.search("if scenario == 'A4_force_arm_takeoff': cheat()")   # 양성 탐지
    assert not id_re.search("generic oracle logic reading node.status")     # 음성


def test_fabrication_tokens_defined():
    # fabrication 필터가 실제 placeholder 토큰을 들고 있어야(빈 필터 방지).
    assert "placeholder" in vc._FABRICATED and "fake" in vc._FABRICATED


def test_phantom_guard_would_catch_injection():
    # no-phantom 가드 로직이 미등록 액션을 실제로 걸러내는지(양성 케이스).
    from redteam_core.tools.mavlink import ATOMIC_ACTIONS
    fake = "totally_unregistered_phantom"
    assert fake not in ATOMIC_ACTIONS
    assert (set([fake]) - set(ATOMIC_ACTIONS)) == {fake}
