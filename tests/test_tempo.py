"""공격 템포 테스트 — 고도화 §P. 결정론·무의존."""
from __future__ import annotations

from redteam_core.tempo import pace, tempo_tradeoff


def test_smash_detected_fast():
    r = pace("active_scan", "smash_and_grab")
    assert r.detected is True and r.mttd_min is not None
    assert r.time_to_effect_min < 1.0            # 즉효


def test_slow_evades_but_takes_time():
    r = pace("active_scan", "low_and_slow")
    assert r.detected is False and r.mttd_min is None   # ∞ MTTD(회피)
    # 저속이라 효과까지 오래(smash 보다 김)
    assert r.time_to_effect_min > pace("active_scan", "smash_and_grab").time_to_effect_min


def test_slow_spoof_accumulates_below_threshold():
    # S1: 저강도 스푸핑이 임계 아래 → 회피, 효과바닥 미달로 다단계 누적.
    r = pace("gnss_spoof", "low_and_slow")
    assert r.detected is False and r.time_to_effect_min >= 60.0


def test_tradeoff_returns_both_tempos():
    tr = tempo_tradeoff("spoof_telemetry")
    assert set(tr) == {"smash_and_grab", "low_and_slow"}
