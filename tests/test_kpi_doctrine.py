"""KPI 7~10 (DoD 교리 보강) 테스트 — 결정론·무의존."""
from __future__ import annotations

from redteam_core.kpi import (
    assessment_quality, mea_reliability, mission_impact, moe_indicators,
)


def test_mea_reliability_in_range():
    m = mea_reliability()
    assert 0.0 < m["mea_overall"] <= 1.0
    # EW TTP는 지오메트리 의존이라 완전 신뢰(1.0) 미만.
    assert m["per_ttp"]["jam"] < 1.0 and m["per_ttp"]["gnss_spoof"] < 1.0


def test_mission_impact_degradation_and_mrtc():
    mi = mission_impact()
    assert 0.0 < mi["mission_degradation_index"] <= 1.0
    assert len(mi["affected_mrt_c"]) >= 1        # 최소 하나의 임무효과 달성


def test_moe_indicators_hierarchy():
    moe = moe_indicators()
    assert "MOE1_effect_achievement" in moe and "MOE2_survivability" in moe
    assert "blind_spot_ratio" in moe["MOE2_survivability"]


def test_assessment_quality_confidence_and_deconfliction():
    aq = assessment_quality()
    assert set(aq["bda_confidence"]) == {"High", "Medium", "Low"}
    assert aq["bda_confidence"]["Low"] >= 1       # 사각지대 = Low 신뢰
    # EW를 우군(no-strike)에 겨누면 데컨플릭션 위반(fratricide+스펙트럼).
    assert aq["deconfliction_violations_sampled"] >= 2
