"""KPI 집계 테스트 (1~3순위) — 결정론·무의존."""
from __future__ import annotations

from redteam_core.kpi import calibration, coverage_gap, dwell


def test_coverage_gap_identifies_ew_ai_blind_spots():
    cg = coverage_gap()
    # 재밍·프롬프트인젝션·모델추출이 사각지대에 포함.
    for sid in ("S30", "S31", "S32", "S33"):
        assert sid in cg["blind_spots"]
    assert 0.0 < cg["blind_spot_ratio"] < 1.0


def test_coverage_gap_stealthy_campaign_includes_c9():
    cg = coverage_gap()
    assert "C9" in cg["stealthy_campaigns"]


def test_dwell_c9_never_detected():
    d = dwell()
    assert d["C9"] is None                     # 완전 은밀 = ∞ 잔존
    assert d["C8"] == 2 and d["C10"] == 2       # 하류 2단계에서 탐지


def test_calibration_brackets_blue_assumed():
    rows = {r["rule"]: r for r in calibration()}
    s6 = rows["S6_Operator_BruteForce"]
    assert s6["measured_boundary"] is not None and s6["blue_assumed"] == 5.0
    assert s6["abs_error"] is not None
