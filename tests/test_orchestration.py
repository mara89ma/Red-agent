"""멀티에이전트 오케스트레이션 테스트 — 고도화 §Q. 결정론·무의존."""
from __future__ import annotations

from redteam_core.orchestration import run_multi_agent_campaign


def test_three_roles_present_in_order():
    r = run_multi_agent_campaign("recon_access")
    assert [role.role for role in r.roles] == ["recon", "exploit", "c2"]


def test_recon_profiles_threat_actors():
    r = run_multi_agent_campaign("recon_access")
    recon = r.roles[0]
    # S6(자격증명)은 APT28·Volt Typhoon이 위협.
    assert any("APT28" in a for a in recon.detail["threat_actors"])


def test_stealthy_for_blindspot_objective():
    # AI 계층(soc_llm_inject)은 사각 → 은밀 성공.
    r = run_multi_agent_campaign("soc_llm_inject")
    assert r.success is True and r.stealthy is True


def test_weapon_not_stealthy():
    r = run_multi_agent_campaign("weapon_effect")
    assert r.stealthy is False        # 무장은 견고(차단/탐지)
