"""레드팀 KPI 스코어카드 §Y 테스트 — 결정론·무의존."""
from __future__ import annotations

from redteam_core.benchmark import format_scorecard, kpi_scorecard


def test_seven_categories():
    sc = kpi_scorecard()
    keys = [c["key"] for c in sc["categories"]]
    assert keys == ["effectiveness", "stealth", "mttd_dwell", "reattack",
                    "coverage", "compliance", "assessment"]


def test_every_metric_has_rating():
    sc = kpi_scorecard()
    for c in sc["categories"]:
        for m in c["metrics"]:
            assert m.rating in ("우수", "양호", "주의")
            assert isinstance(m.value, float)


def test_counts_sum_matches_metrics():
    sc = kpi_scorecard()
    n = sum(len(c["metrics"]) for c in sc["categories"])
    assert sum(sc["counts"].values()) == n


def test_overall_and_headline():
    sc = kpi_scorecard()
    assert sc["overall"] in ("우수", "양호", "주의")
    assert len(sc["headline"]) == 3


def test_lower_better_rating_direction():
    # OPSEC 노출(낮을수록 우수)이 목표 이하면 우수여야 함.
    sc = kpi_scorecard()
    comp = next(c for c in sc["categories"] if c["key"] == "compliance")
    opsec = next(m for m in comp["metrics"] if "OPSEC" in m.kpi)
    assert opsec.higher_better is False
    if opsec.value <= opsec.target:
        assert opsec.rating == "우수"


def test_format_renders():
    txt = format_scorecard(kpi_scorecard())
    assert "스코어카드" in txt and "헤드라인" in txt and "종합" in txt
