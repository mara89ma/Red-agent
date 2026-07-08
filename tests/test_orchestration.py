"""CMT 직무 오케스트레이션 테스트 — 미군 사이버작전 조직. 결정론·무의존."""
from __future__ import annotations

from redteam_core.orchestration import run_cmt_campaign, run_multi_agent_campaign


def test_cmt_work_roles_in_order():
    r = run_cmt_campaign("recon_access")
    assert [role.role for role in r.roles] == ["MC", "TDNA", "ION", "BDA"]


def test_mc_reports_engagement_authority():
    r = run_cmt_campaign("recon_access")
    mc = r.roles[0]
    assert mc.detail["verdict"] in ("PERMITTED", "ESCALATE", "BLOCKED")


def test_tdna_profiles_threat_actors():
    r = run_cmt_campaign("recon_access")
    tdna = r.roles[1]
    assert any("APT28" in a for a in tdna.detail["threat_actors"])


def test_stealthy_for_ai_blindspot():
    r = run_cmt_campaign("soc_llm_inject")
    assert r.success is True and r.stealthy is True


def test_alias_backward_compatible():
    assert run_multi_agent_campaign is run_cmt_campaign
