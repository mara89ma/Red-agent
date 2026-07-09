"""교리 5종 확장 테스트 — JADC2·Mosaic·OODA·Information·MissionCommand. 결정론."""
from __future__ import annotations

from redteam_core.information import attack_reporting_chain
from redteam_core.jadc2 import mesh_degradation_test, multi_sensor_consistency_attack
from redteam_core.mission_command import MissionProfile, run_mission_command
from redteam_core.mosaic import (
    attack_recombination_logic, introspect_judges, verify_judge_independence,
)
from redteam_core.ooda import ooda_race, orient_phase_denial


# ── JADC2 융합 ──
def test_jadc2_false_positive_fusion():
    # 5축 각 0.6(개별 미탐<1.0) → 합 3.0≥2.5 → 거짓 상관 발화.
    r = multi_sensor_consistency_attack({a: 0.6 for a in
        ("gnss", "imu", "telemetry", "datalink", "eo_ir")}, mode="false_positive")
    assert r.individually_stealthy and r.correlator_fires and r.success


def test_jadc2_false_negative_noise():
    r = multi_sensor_consistency_attack({a: 0.4 for a in
        ("gnss", "imu", "telemetry", "datalink", "eo_ir")}, mode="false_negative")
    assert not r.correlator_fires and r.success       # 진짜를 노이즈로 위장


def test_jadc2_mesh_graceful_vs_catastrophic():
    assert mesh_degradation_test(5, 2).graceful is True       # 3축 남음
    assert mesh_degradation_test(5, 4).graceful is False      # 1축=상관 붕괴


# ── Mosaic 재조합/독립성 ──
def test_mosaic_real_introspection():
    # 하드코딩 아니라 실제 ensemble.py 검사: signal=veto, 조언 judge 존재.
    j = introspect_judges()
    assert j["signal"]["veto"] is True and j["experience"]["veto"] is False
    assert "signal_verified" in j["signal"]["ctx_fields"]


def test_mosaic_advisory_judges_are_independent():
    # 실 소스 검증: 조언 judge 가 서로 다른 1차 소스 → common-mode 아님(정직).
    r = verify_judge_independence()
    assert r.common_mode is False and r.veto_judges == ["signal"]


def test_mosaic_evidence_poison_contained_by_veto():
    r = attack_recombination_logic("evidence")
    assert "llm" in r.affected_judges and r.veto_preserves is True  # veto 미의존→보존


# ── OODA ──
def test_ooda_orient_paralysis():
    assert orient_phase_denial(3).orient_paralyzed is True
    assert orient_phase_denial(1).orient_paralyzed is False


def test_ooda_race_inside_loop():
    r = ooda_race(2.0, 5.0)
    assert r.winner == "red" and r.inside_loop is True


# ── Information ──
def test_information_forge_passes_without_signature():
    assert attack_reporting_chain("S100", integrity_signed=False).success is True
    assert attack_reporting_chain("S100", integrity_signed=True).success is False


# ── Mission Command ──
def test_mission_command_autonomous_execution():
    p = MissionProfile("항법거부+정찰", ["nav_denial", "recon"], roe_ceiling=2)
    r = run_mission_command(p)
    assert r.autonomous is True and r.end_state_achieved is True
    assert any(d.action == "executed" for d in r.decisions)


def test_mission_command_withholds_beyond_roe():
    # 무장(권한4)을 상한1로 요청 → 자율 보류.
    p = MissionProfile("무장", ["weapon_effect"], roe_ceiling=1)
    r = run_mission_command(p)
    assert any(d.action == "withheld_roe" for d in r.decisions)
    assert r.end_state_achieved is False
