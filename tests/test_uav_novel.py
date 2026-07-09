"""신규 UAV 시나리오 S60~S62 테스트 — 실 아티팩트 + 판정. 결정론·무의존."""
from __future__ import annotations

from redteam_core.payloads.uav_novel import NOVEL_SCENARIOS
from redteam_core.sandbox import analyze
from redteam_core.mapping.uav_coverage import RED_COVER, UAV_MATRIX


def test_three_new_scenarios_fill_gap():
    assert set(NOVEL_SCENARIOS) == {"S60", "S61", "S62"}


def test_s60_satellite_c2_blind():
    r = analyze(NOVEL_SCENARIOS["S60"]())
    assert r.scenario == "S60" and r.blind_spot is True   # 위성 C2 은닉


def test_s61_gnss_capture_walkoff():
    p = NOVEL_SCENARIOS["S61"]()
    assert p.data["steps"] == 6 and len(p.data["walk_coords"]) == 6
    assert analyze(p).verdict == "malicious"


def test_s62_ekf_fault_uses_sensors():
    p = NOVEL_SCENARIOS["S62"]()
    assert set(p.data["sensors"]) == {"imu", "baro", "mag"}
    assert analyze(p).blind_spot is True                  # EKF 게이트 통과=은밀


def test_new_technique_and_mappings_in_matrix():
    matrix_ids = {tid for _, tid, _, _ in UAV_MATRIX}
    assert "T1090.002" in matrix_ids                      # 위성 C2 신규 기법 반영
    assert RED_COVER["T1090.002"].startswith("S60")
    assert "S61" in RED_COVER["T0831"] and "S62" in RED_COVER["T0835"]
