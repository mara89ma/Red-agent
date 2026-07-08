"""데이터 유출 시나리오 테스트 — S35~S38. 결정론·무의존."""
from __future__ import annotations

from redteam_core.assessment import OBJECTIVES
from redteam_core.campaigns import run_chain
from redteam_core.exfil import EXFIL_SCENARIOS, run_exfil


def test_exfil_objectives_registered():
    for obj in ("data_exfiltration", "covert_exfil", "staged_exfil", "crypto_key_exfil"):
        assert obj in OBJECTIVES


def test_exfil_scenarios_are_blindspots():
    # 유출 전용 탐지룰 미배포 → 전부 사각지대(은밀 달성).
    for sid in EXFIL_SCENARIOS:
        r = run_exfil(sid)
        assert r["verdict"] == "achieved" and r["detected"] is None


def test_crypto_key_scenario_present():
    s38 = EXFIL_SCENARIOS["S38"]
    assert "암호키" in s38["name"] and "S18" in s38["note"]


def test_exfil_campaigns():
    # C11(암호키), C12(스테이징→대량유출) 존재 + 실행.
    for cid in ("C11", "C12"):
        cr = run_chain(cid)
        assert cr.verdict in ("stealthy", "detected")
    # C12 는 자격증명(회피) 이후 전부 사각 → 은밀.
    assert run_chain("C12").verdict == "stealthy"
