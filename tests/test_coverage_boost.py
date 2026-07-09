"""커버리지 최대화 보강(S56~S62) 테스트 — C2 은닉 + advanced. 결정론·무의존."""
from __future__ import annotations

from redteam_core.transport.covert_c2 import (
    encode_c2, encrypt_c2, obfuscate_c2, tunnel_c2, roundtrip_ok,
)
from redteam_core.payloads.advanced import ADVANCED_SCENARIOS
from redteam_core.sandbox import analyze
from redteam_core.mapping.uav_coverage import effective_summary, gaps_by_scope


def test_covert_c2_roundtrip_is_real():
    assert roundtrip_ok() is True                       # 4기법 실 변환→복원 일치(가짜 아님)


def test_covert_c2_techniques():
    assert encode_c2(b"x").technique == "T1132"
    assert encrypt_c2(b"x").technique == "T1573"
    assert obfuscate_c2(b"x").technique == "T1001"
    assert tunnel_c2(b"x").technique == "T1572"


def test_encrypt_actually_changes_bytes():
    f = encrypt_c2(b"ARM")
    assert f.data != b"ARM" and bytes(b ^ 0x5A for b in f.data) == b"ARM"


def test_advanced_scenarios_detected():
    verdicts = {}
    for sid, fn in ADVANCED_SCENARIOS.items():
        verdicts[sid] = analyze(fn()).verdict
    assert verdicts["S57"] == "malicious"               # 파괴
    assert verdicts["S58"] == "malicious"               # rootkit
    assert verdicts["S59"] == "malicious"               # fw mode
    assert verdicts["S60"] == "malicious"               # auth 변조
    assert verdicts["S62"] == "malicious"               # 탈취
    assert analyze(ADVANCED_SCENARIOS["S61"]()).blind_spot is True   # 유출 대체매체=사각


def test_effective_coverage_now_100():
    e = effective_summary()
    assert e["effective_pct"] == 100.0                  # 유효 커버리지 100%
    assert gaps_by_scope()["reinforce"] == []           # 보강후보 소진
