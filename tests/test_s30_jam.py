"""S30 GNSS 재밍 시나리오 배선 테스트 — 결정론·무의존."""
from __future__ import annotations

from redteam_core.assessment import OBJECTIVES, adaptive_engage, run_engagement


def test_s30_objective_registered():
    assert "nav_jam_denial" in OBJECTIVES and OBJECTIVES["nav_jam_denial"] == ["jam"]


def test_s30_strong_jam_stealthy_navdenial():
    # 근접 고출력 재밍: 효과 달성 + 사각지대(미탐지) → 은밀 달성.
    ca = run_engagement("jam", geometry={"jammer_eirp_dbm": 40, "jammer_dist_m": 100,
                                         "signal_eirp_dbm": 16, "signal_dist_m": 20000,
                                         "freq_mhz": 1575.42})
    assert ca.moe_effect is True
    assert ca.detected is None            # blue 미매핑 = 사각지대
    assert ca.effective is True and ca.reattack.needed is False


def test_s30_weak_jam_no_effect():
    ca = run_engagement("jam", geometry={"jammer_eirp_dbm": -10, "jammer_dist_m": 20000,
                                         "signal_eirp_dbm": 16, "signal_dist_m": 20000,
                                         "freq_mhz": 1575.42})
    assert ca.moe_effect is False         # J/S 번스루 미달


def test_s30_adaptive_engage_achieves_via_blindspot():
    r = adaptive_engage("nav_jam_denial")
    assert r.verdict == "achieved" and r.winning_ttp == "jam"
