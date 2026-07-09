"""UAV 특화 APT 에뮬레이션 테스트 — 실 시나리오 합성 검증. 결정론·무의존."""
from __future__ import annotations

from redteam_core.integrations.uav_apt import UAV_APT_EMULATION, run_uav_apt, uav_apt_names


def test_nine_uav_apt_profiles():
    assert len(UAV_APT_EMULATION) == 9


def test_all_chains_compose_known_scenarios():
    # 임의 창작 금지 — 전 체인이 알려진 S-시나리오만 사용.
    for name in uav_apt_names():
        r = run_uav_apt(name)
        assert r.valid is True, f"{name}: {r.chain}"
        assert len(r.chain) >= 3


def test_turla_satellite_c2_chain():
    r = run_uav_apt("Turla (G0010, 위성 C2)")
    assert r.chain[0] == "S3" and "S17" in r.chain      # SATCOM MITM → SAR 유출
    assert r.origin == "Russia FSB"


def test_rq170_gnss_hijack_chain():
    r = run_uav_apt("RQ-170 GNSS Hijack (Iran 2011)")
    assert "S30" in r.chain and "S1" in r.chain          # 재밍 + 스푸핑
    assert r.chain[-1] == "S20"                          # 강제착륙(Failsafe 억제)


def test_multisensor_ekf_defeat_uses_sensor_scenarios():
    r = run_uav_apt("Multi-Sensor Deception (EKF Defeat)")
    assert set(["S56", "S57", "S58", "S59"]).issubset(set(r.chain))
