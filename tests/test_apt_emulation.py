"""APT 에뮬레이션 테스트 — 고도화 §O. 결정론·무의존."""
from __future__ import annotations

import pytest

from redteam_core.integrations import apt_emulation as apt


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("CTID_PLAN_URL", raising=False)


def test_ctid_fallback_uses_seed_plan():
    assert apt.status()["mode"] == "fallback"
    assert apt.emulation_plan("APT28 (G0007)") == ["S34", "S6", "S10", "S13", "S15", "S11", "S17"]
    assert len(apt.APT_EMULATION) == 8            # 확장된 8개 APT


def test_run_apt_emulation_detection_profile():
    r = apt.run_apt_emulation("APT28 (G0007)")
    # 무장(S11)·모바일GCS(S10) 등 배포룰에서 탐지됨.
    assert r.verdict == "detected" and "S11" in r.detected_at


def test_aml_adversary_fully_stealthy():
    # AML 계열은 전 단계(S29 RAG·S7 온보드·S32·S33·S8) 미배포 = 완전 사각.
    r = apt.run_apt_emulation("AML Adversary (ATLAS)")
    assert r.verdict == "stealthy" and r.detected_at == []
    assert all(d is None for _s, d in r.steps)


def test_korea_relevant_apts_present():
    for a in ("Lazarus (G0032)", "Kimsuky (G0094)"):
        assert a in apt.APT_EMULATION


def test_next_ttp_follows_pattern():
    assert apt.next_ttp_by_pattern("Volt Typhoon (G1017)") == "S34"
    assert apt.next_ttp_by_pattern("Volt Typhoon (G1017)", ["S34"]) == "S6"
    assert apt.next_ttp_by_pattern(
        "Volt Typhoon (G1017)", ["S34", "S6", "S27", "S26", "S24", "S2"]) is None


def test_ctid_env_flips_mode(monkeypatch):
    monkeypatch.setenv("CTID_PLAN_URL", "https://github.com/center-for-threat-informed-defense/adversary_emulation_library")
    assert apt.ctid_available() is True and apt.status()["mode"] == "real"
