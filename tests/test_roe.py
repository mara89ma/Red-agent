"""RoE 게이트 테스트 — 고도화 §B. 결정론·무의존(동언님 테스트 스타일).

교전권한 레벨·CDE·PID·ConOps·데컨플릭션(스펙트럼/우군)까지 판정 확인.
"""
from __future__ import annotations

from redteam_core.roe import (
    AuthorityLevel, CdeTier, estimate_cde, required_authority,
    evaluate_roe, RoeVerdict,
)

_PROFILE = {
    "available_authority": "COMPONENT",
    "conops": {"permitted_effects": ["Collect", "Manipulate", "Deny(Disrupt)"]},
    "pid_required_for": ["write_highrisk", "physical_irreversible"],
    "no_strike_list": [1, 254, 255],
    "restricted_targets": [777],
    "spectrum": {"jceoi_deconflicted": False},
}
_GROUND = {"armed": False, "in_flight": False, "alt_rel": 0.0, "mode": "GUIDED"}
_TGT = {"sysid": 42, "pid": True}


def test_read_action_permitted_no_authority():
    d = evaluate_roe("recon_heartbeat", _GROUND, _TGT, _PROFILE)
    assert d.verdict == RoeVerdict.PERMITTED
    assert d.required_authority == "NONE"


def test_offensive_effect_outside_conops_blocked():
    # force_arm = Deny(Destroy) ∉ ConOps 허용효과 → BLOCKED.
    d = evaluate_roe("force_arm", _GROUND, _TGT, _PROFILE)
    assert d.verdict == RoeVerdict.BLOCKED
    assert any("ConOps" in u for u in d.unmet_conditions)


def test_missing_pid_blocks_highrisk():
    d = evaluate_roe("param_set_safety", _GROUND, {"sysid": 42, "pid": False}, _PROFILE)
    assert d.verdict == RoeVerdict.BLOCKED
    assert any("PID" in u for u in d.unmet_conditions)


def test_ew_requires_spectrum_deconfliction():
    # gnss_spoof = Manipulate(ConOps OK) + PID OK 이지만 JCEOI 미승인 → BLOCKED.
    d = evaluate_roe("gnss_spoof", _GROUND, _TGT, _PROFILE)
    assert d.verdict == RoeVerdict.BLOCKED
    assert any("JCEOI" in c or "spectrum" in c for c in d.deconfliction_conflicts)


def test_ew_permitted_when_deconflicted():
    prof = {**_PROFILE, "spectrum": {"jceoi_deconflicted": True}}
    d = evaluate_roe("gnss_spoof", _GROUND, _TGT, prof)
    # 스펙트럼 승인 후엔 데컨플릭션 통과. 권한은 CDE(광역효과)로 상향될 수 있음.
    assert not d.deconfliction_conflicts
    assert d.verdict in (RoeVerdict.PERMITTED, RoeVerdict.ESCALATE)


def test_fratricide_no_strike_blocked():
    d = evaluate_roe("set_mode", _GROUND, {"sysid": 1, "pid": True}, _PROFILE)
    assert d.verdict == RoeVerdict.BLOCKED
    assert any("fratricide" in c for c in d.deconfliction_conflicts)


def test_cde_area_effect_raises_authority():
    # 광역효과(gnss_spoof)는 CDE 상향 → 요구 권한도 상향.
    cde_point = estimate_cde("set_mode", _GROUND)
    cde_area = estimate_cde("gnss_spoof", _GROUND)
    assert cde_area > cde_point


def test_required_authority_takes_max_of_gate_and_cde():
    r = required_authority("low", CdeTier.HIGH)
    assert r == AuthorityLevel.JFC        # CDE 하한이 gate 기본을 상회


def test_core_untouched_and_reversibility_reused():
    from redteam_core.safety.reversibility import classify  # noqa: F401
    from redteam_core.graph.build import build_graph  # noqa: F401
