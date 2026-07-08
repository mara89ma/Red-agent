"""외부 연동 계층 테스트 — 고도화 §O. env 없는 폴백 경로 검증(결정론)."""
from __future__ import annotations

import os

import pytest

from redteam_core.integrations import ai_attack, caldera, integration_status, sitl


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for k in ("AI_ATTACK_PROVIDER", "AI_TARGET_URL", "CALDERA_URL", "CALDERA_API_KEY",
              "MAVLINK_ENDPOINT", "TAXII_URL", "TAXII_COLLECTION", "CTID_PLAN_URL"):
        monkeypatch.delenv(k, raising=False)


def test_all_fallback_without_env():
    st = integration_status()
    assert all(v["mode"] == "fallback" for v in st.values())
    assert set(st) == {"ai_attack", "caldera", "sitl", "threat_intel", "apt_emulation",
                       "archive_tools"}


def test_ai_attack_fallback_is_blindspot():
    r = ai_attack.run_ai_attack("prompt_injection")
    assert r["mode"] == "fallback" and r["detected"] is None   # 사각지대
    assert r["mitre"] == "AML.T0051"


def test_caldera_fallback_runs_internal_chain():
    r = caldera.run_operation("C9")
    assert r["mode"] == "fallback" and r["verdict"] == "stealthy"


def test_sitl_fallback_no_transmission():
    r = sitl.inject_gps_spoof()
    assert r["mode"] == "fallback" and r["frame_bytes"] > 0


def test_env_flips_availability(monkeypatch):
    # env 지정 시 available()가 True 시도(라이브러리 없으면 여전히 False = 정직).
    monkeypatch.setenv("CALDERA_URL", "http://caldera.local:8888")
    monkeypatch.setenv("CALDERA_API_KEY", "k")
    assert caldera.available() is True and caldera.status()["mode"] == "real"


def test_sitl_endpoints_read_env(monkeypatch):
    monkeypatch.setenv("MAVLINK_ENDPOINT", "10.0.0.5:14550")
    assert sitl.endpoints()["mavlink"] == "10.0.0.5:14550"
