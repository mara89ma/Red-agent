"""APT 에뮬레이션 테스트 — 고도화 §O. 결정론·무의존."""
from __future__ import annotations

import pytest

from redteam_core.integrations import apt_emulation as apt


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("CTID_PLAN_URL", raising=False)


def test_ctid_fallback_uses_seed_plan():
    assert apt.status()["mode"] == "fallback"
    assert apt.emulation_plan("APT28 (G0007)") == ["S6", "S10", "S15", "S11", "S17"]


def test_run_apt_emulation_detection_profile():
    r = apt.run_apt_emulation("APT28 (G0007)")
    # 무장(S11)·야간명령(S15) 등 배포룰에서 탐지됨.
    assert r.verdict == "detected" and "S11" in r.detected_at


def test_aml_adversary_mostly_blind():
    # AML 계열(S5 배포/S32·S33·S7 사각) — S7 사각지대 포함.
    r = apt.run_apt_emulation("AML Adversary (ATLAS)")
    blind = [s for s, d in r.steps if d is None]
    assert "S32" in blind and "S33" in blind


def test_next_ttp_follows_pattern():
    assert apt.next_ttp_by_pattern("Volt Typhoon (G1017)") == "S6"
    assert apt.next_ttp_by_pattern("Volt Typhoon (G1017)", ["S6"]) == "S26"
    assert apt.next_ttp_by_pattern("Volt Typhoon (G1017)", ["S6", "S26", "S24"]) is None


def test_ctid_env_flips_mode(monkeypatch):
    monkeypatch.setenv("CTID_PLAN_URL", "https://github.com/center-for-threat-informed-defense/adversary_emulation_library")
    assert apt.ctid_available() is True and apt.status()["mode"] == "real"
