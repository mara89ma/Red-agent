"""레드팀 KPI 개선 테스트 — 목표 근거화 + 라운드별 추세. 결정론·무의존."""
from __future__ import annotations

from redteam_core.benchmark import (
    TARGETS, format_trend, kpi_scorecard, project_rounds, trend_summary,
)


def test_every_scorecard_metric_has_source():
    sc = kpi_scorecard()
    for c in sc["categories"]:
        for m in c["metrics"]:
            assert m.source and m.source in {t["source"] for t in TARGETS.values()}


def test_targets_have_rationale_and_source():
    for k, t in TARGETS.items():
        assert t["source"] and t["rationale"] and "value" in t and "higher_better" in t


def test_round0_is_baseline():
    rounds = project_rounds(4)
    assert rounds[0]["round"] == 0 and rounds[0]["closed"] == 0


def test_gap_closure_monotonic():
    rounds = project_rounds(4)
    # 사각비율 단조 감소, 탐지율 단조 증가.
    for a, b in zip(rounds, rounds[1:]):
        assert b["blind_ratio"] <= a["blind_ratio"]
        assert b["detection_rate"] >= a["detection_rate"]
        assert b["mttd_steps"] <= a["mttd_steps"]


def test_trend_converges_to_zero_blind():
    rounds = project_rounds(4)
    s = trend_summary(rounds)
    assert s["converged"] is True
    assert s["blind_ratio"][1] == 0.0 and s["detection_rate"][1] == 1.0


def test_format_trend_labels_projection():
    txt = format_trend(project_rounds(3))
    assert "투영" in txt and "실측 이력 아님" in txt
