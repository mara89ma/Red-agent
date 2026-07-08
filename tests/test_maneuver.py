"""기동/측면이동 테스트 — 고도화 §G. 결정론·무의존."""
from __future__ import annotations

from redteam_core.maneuver import run_campaign, simple_paths, ATTACKER


def test_simple_paths_shortest_first():
    paths = simple_paths(ATTACKER, "gnss_rcv")
    assert len(paths) >= 2                       # RF 직접 + 네트워크 경로
    assert len(paths[0]) <= len(paths[-1])


def test_gnss_reroutes_from_blocked_rf_to_network():
    # RF 직접(1-hop) 막힘 → 네트워크 경로로 재경로해 도달.
    r = run_campaign("gnss_rcv")
    assert r.verdict == "reached"
    assert r.attempts >= 2                        # 재경로 발생
    assert r.winning_path[-1] == "gnss_rcv"
    assert "gcs" in r.winning_path and "c2_link" in r.winning_path


def test_weapon_maneuver_reaches_but_effect_blocked():
    # 무장까지 측면이동은 되나 최종 효과 hop(범주형)에서 차단 → campaign blocked.
    r = run_campaign("weapon")
    assert r.verdict == "blocked"
    assert any(h.phase == "lateral_movement" and h.status == "gained" for h in r.hops)
    assert r.hops[-1].status == "blocked"


def test_lateral_movement_phase_present():
    r = run_campaign("gnss_rcv")
    phases = [h.phase for h in r.hops]
    assert "lateral_movement" in phases


def test_core_untouched():
    from redteam_core.graph.build import build_graph  # noqa: F401
