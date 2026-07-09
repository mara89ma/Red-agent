"""xbow식 능력 벤치마크 §Y 테스트 — 하니스·스위트·채점·외부. 결정론·무의존."""
from __future__ import annotations

from redteam_core.benchmark import (
    Challenge, UAV_BENCHMARKS, external_status, run_challenge, run_suite,
)


def test_suite_runs_and_scores():
    sb = run_suite(UAV_BENCHMARKS)
    assert len(sb.results) == len(UAV_BENCHMARKS)
    assert 0 < sb.total_score <= sb.max_score
    assert 0 <= sb.evasion_pct <= 100


def test_stealthy_scores_full_difficulty():
    # 사각지대 목표(soc_llm_inject)는 은밀 관통 → 난이도 만점.
    r = run_challenge(Challenge("BX", "LLM 인젝션", 2, "soc_llm_inject", "ai"))
    assert r.outcome == "stealthy" and r.score == 2.0


def test_blocked_scores_zero():
    # weapon_effect 는 차단 → 0점.
    r = run_challenge(Challenge("BY", "무장", 3, "weapon_effect", "sim"))
    assert r.outcome == "blocked" and r.score == 0.0


def test_scoreboard_tier_breakdown():
    sb = run_suite(UAV_BENCHMARKS)
    tiers = sb.by_tier()
    assert set(tiers) <= {1, 2, 3} and sum(t["n"] for t in tiers.values()) == len(UAV_BENCHMARKS)


def test_captured_and_stealthy_counts():
    sb = run_suite(UAV_BENCHMARKS)
    assert sb.captured >= sb.stealthy          # 관통 ⊇ 은밀
    assert sb.stealthy >= 8                     # 사각지대 다수 → 은밀 관통 다수


def test_external_adapter_reference_mode():
    st = external_status()
    assert any(b["name"].startswith("xbow") for b in st)
    assert all(b["mode"] in ("real", "reference") for b in st)
