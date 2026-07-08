"""킬체인 관통 테스트 — 고도화 §J. 결정론·무의존."""
from __future__ import annotations

from redteam_core.killchain import run_killchain


def test_full_stealthy_penetration_gnss_with_covert_techniques():
    # gnss: 은밀 지속(credential)+은밀 C2(common_port) → 완전+은밀 관통.
    r = run_killchain("gnss_rcv", persistence="credential_foothold", c2="common_port")
    assert r.completed is True and r.stealthy is True
    assert len(r.stages) == 7
    assert all(s.status == "수행" for s in r.stages)


def test_noisy_techniques_complete_but_detected():
    # 펌웨어 임플란트 + 불량 라우터 → 관통은 되나 탐지(은밀 실패).
    r = run_killchain("gnss_rcv", persistence="firmware_implant", c2="rogue_router")
    assert r.completed is True and r.stealthy is False
    detected = [s.stage for s in r.stages if s.status == "탐지"]
    assert "설치/지속" in detected and "C2" in detected


def test_weapon_chain_breaks_at_actions_on_objectives():
    # 무장: 6단계까지 수행되나 목표행동(범주형)에서 차단 → 미완주.
    r = run_killchain("weapon", persistence="credential_foothold", c2="common_port")
    assert r.completed is False
    assert r.stages[-1].stage == "목표행동" and r.stages[-1].status == "차단"


def test_all_seven_stages_present_in_order():
    r = run_killchain("gnss_rcv")
    assert [s.stage for s in r.stages] == ["정찰", "무기화", "전달", "악용", "설치/지속", "C2", "목표행동"]


def test_core_untouched():
    from redteam_core.graph.build import build_graph  # noqa: F401
