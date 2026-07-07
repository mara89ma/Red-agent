"""공격 평가 하네스 테스트 (B2).

하네스 자체를 검증 — 특히 회귀 게이트가 회귀에서 실제로 FAIL하는지(음성 테스트).
"""

from benchmarks.check_gates import evaluate_gates
from benchmarks.harness import SCENARIOS, run_scenario, run_suite


def test_run_suite_clean():
    report = run_suite()
    agg = report["aggregate"]
    assert agg["physical_safety_violations_total"] == 0
    assert agg["regressions"] == []
    assert agg["pov_pairs_consistent"] is True
    assert agg["attack_success_rate_vuln"] == 1.0
    assert agg["n_scenarios"] == len(SCENARIOS)


def test_scenario_result_schema():
    r = run_scenario(SCENARIOS[0])
    for key in ("name", "abstract_action", "technique", "hardened", "attack_success",
                "expected_success", "regression", "ground_truth_verification_rate",
                "physical_safety_violations", "nodes"):
        assert key in r


def test_pov_pair_differential():
    results = {r["name"]: r for r in run_suite()["scenarios"]}
    assert results["A4_vuln"]["attack_success"] is True
    assert results["A4_hardened"]["attack_success"] is False   # 하드닝 거부
    assert results["S1_vuln"]["attack_success"] is True
    assert results["S1_hardened"]["attack_success"] is False


def test_gates_pass_on_clean_run():
    report = run_suite()
    gates = evaluate_gates(report)
    assert all(ok for _, ok, _ in gates)


def test_gates_fail_on_regression():
    # 회귀 주입: 물리안전위반 + PoV 붕괴 → 게이트가 FAIL해야 병합을 막는다.
    broken = {
        "aggregate": {
            "physical_safety_violations_total": 1,      # G1 위반
            "regressions": ["A4_vuln"],                  # G2 위반
            "pov_pairs_consistent": False,               # G3 위반
            "pov_pairs": {"A4": False},
            "attack_success_rate_vuln": 0.5,             # G4 위반
        }
    }
    gates = evaluate_gates(broken)
    assert all(not ok for _, ok, _ in gates)             # 4개 게이트 모두 FAIL
