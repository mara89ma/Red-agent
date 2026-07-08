"""적응형 재계획 테스트 — 고도화 §E. 결정론·무의존."""
from __future__ import annotations

from redteam_core.assessment import adaptive_engage


def test_recon_evades_by_lowering_intensity():
    # active_scan: 효과 바닥(1) < blue 임계(5) → 회피창 존재 → 강도 하향으로 달성.
    r = adaptive_engage("recon_access")
    assert r.verdict == "achieved" and r.winning_ttp == "active_scan"
    # 마지막 시도의 강도가 blue 임계(5) 미만
    assert r.trace[-1][1] < 5.0


def test_nav_denial_pivots_to_blindspot_when_no_evasion_window():
    # gnss_spoof: 효과 바닥(0.05) > blue 게이트(0.0238) → 효과 내면 항상 탐지 →
    # jam(사각지대)으로 전환해 달성.
    r = adaptive_engage("nav_denial")
    assert r.verdict == "achieved" and r.winning_ttp == "jam"
    actions = [t[0] for t in r.trace]
    assert "gnss_spoof" in actions and actions[-1] == "jam"   # 스푸핑→전환→재밍


def test_weapon_effect_blocked_when_all_ttps_categorical():
    # force_arm·unauthorized_command 둘 다 범주형 → 회피 불가 → 소진 → blocked.
    r = adaptive_engage("weapon_effect")
    assert r.verdict == "blocked" and r.winning_ttp is None
    assert {t[0] for t in r.trace} == {"force_arm", "unauthorized_command"}


def test_trace_records_reattack_adjustments():
    r = adaptive_engage("nav_denial")
    adjustments = [ca.reattack.adjustment for _, _, ca in r.trace]
    assert "lower_intensity" in adjustments or "switch_ttp" in adjustments
