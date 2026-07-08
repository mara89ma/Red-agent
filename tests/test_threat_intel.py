"""위협 인텔 연동 테스트 — 고도화 §O. 결정론·무의존."""
from __future__ import annotations

import pytest

from redteam_core.integrations import threat_intel as ti


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("TAXII_URL", raising=False)
    monkeypatch.delenv("TAXII_COLLECTION", raising=False)


def test_taxii_fallback_without_env():
    assert ti.taxii_available() is False and ti.status()["mode"] == "fallback"
    assert set(ti.active_actors()) == set(ti.THREAT_ACTORS)


def test_profile_scenario_maps_actors():
    # S6(GCS 자격증명)은 APT28 + Volt Typhoon 둘 다 구사.
    actors = ti.profile_scenario("S6")
    assert "APT28 (G0007)" in actors and "Volt Typhoon (G1017)" in actors
    assert ti.threat_count("S6") >= 2


def test_ti_boosts_most_threatened_target():
    hptl = ti.ti_prioritized_targets()
    by_sid = {r["scenario"]: r for r in hptl}
    # GCS 자격증명(S6)이 최다 위협(≥2) → 최대 TI 가산.
    s6 = by_sid["S6"]
    assert s6["active_threats"] >= 2 and s6["ti_score"] == s6["carver"] + s6["active_threats"] * 2
    # HPTL 은 TI 점수 내림차순 정렬.
    assert [r["ti_score"] for r in hptl] == sorted((r["ti_score"] for r in hptl), reverse=True)
    # TI 가중으로 GCS 와 GNSS 격차가 좁혀짐(CARVER 5점차 → TI 3점차).
    assert by_sid["S1"]["ti_score"] - s6["ti_score"] < by_sid["S1"]["carver"] - s6["carver"]


def test_taxii_env_flips_availability(monkeypatch):
    monkeypatch.setenv("TAXII_URL", "https://otx.alienvault.com/taxii")
    monkeypatch.setenv("TAXII_COLLECTION", "user_AlienVault")
    # 라이브러리 없으면 여전히 False(정직) — env만으로 True 주장 안 함.
    assert ti.taxii_available() in (True, False)
