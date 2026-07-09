"""커버리지 최대화 보강(S65~S71) 테스트 — C2 은닉 + advanced. 결정론·무의존."""
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
    assert verdicts["S66"] == "malicious"               # 파괴
    assert verdicts["S67"] == "malicious"               # rootkit
    assert verdicts["S68"] == "malicious"               # fw mode
    assert verdicts["S69"] == "malicious"               # auth 변조
    assert verdicts["S71"] == "malicious"               # 탈취
    assert analyze(ADVANCED_SCENARIOS["S70"]()).blind_spot is True   # 유출 대체매체=사각


def test_effective_coverage_now_100():
    e = effective_summary()
    assert e["effective_pct"] == 100.0                  # 진짜불가 3개만 제외 → 100%
    assert gaps_by_scope()["reinforce"] == []           # 보강후보 소진


def test_conservative_total_coverage_over_95():
    # 보수적: 전체 매트릭스(범위 재정의 없음) 기준 ≥95%.
    e = effective_summary()
    assert e["total_pct"] >= 95.0                       # 97.1%
    assert e["excluded"] == 3                           # 진짜 불가(공격자 자기 인프라)만


def test_collection_scenarios_real_and_blind():
    from redteam_core.payloads.collection import COLLECTION_SCENARIOS
    assert len(COLLECTION_SCENARIOS) == 8
    for tid, fn in COLLECTION_SCENARIOS.items():
        p = fn()
        r = analyze(p)
        assert p.data and p.technique                    # 실 아티팩트
        assert r.blind_spot is True                      # 정직: blue 로그 없음(사각)
