"""Metasploit MCP/RPC + CVE MCP 연동 테스트 — §Q. env 없는 폴백 검증(결정론)."""
from __future__ import annotations

import pytest

from redteam_core.integrations import cve_intel, integration_status, metasploit


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for k in ("MSF_MCP_URL", "MSF_RPC_HOST", "MSF_RPC_PASSWORD", "CVE_MCP_URL"):
        monkeypatch.delenv(k, raising=False)


def test_status_includes_new_integrations():
    st = integration_status()
    assert "metasploit" in st and "cve_intel" in st
    assert st["metasploit"]["mode"] == "fallback" and st["cve_intel"]["mode"] == "fallback"


def test_msf_maps_it_scenarios_dry():
    r = metasploit.run_scenario("S6")           # http_login
    assert r["mode"] == "fallback(dry)" and "http_login" in r["module"]


def test_msf_unmapped_uav_scenario():
    r = metasploit.run_scenario("S1")           # UAV 특화 → msf 미매핑
    assert r["mode"] == "unmapped"


def test_cve_fallback_static_registry():
    r = cve_intel.lookup_cve("CVE-2015-3789")   # 정적 레지스트리
    assert r["mode"] == "fallback(static)" and r["record"]["scenario"] == "S42"


def test_cve_for_scenario():
    assert any(c["scenario"] == "S40" for c in cve_intel.cves_for_scenario("S40"))


def test_msf_env_flips_mode(monkeypatch):
    monkeypatch.setenv("MSF_MCP_URL", "http://msf-mcp.local:8080")
    assert metasploit.available() is True and metasploit.status()["transport"] == "mcp"
