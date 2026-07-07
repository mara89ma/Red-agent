"""TI 피드·카탈로그·커버리지 테스트 (B9). 전부 오프라인 결정론."""

import pytest

from redteam_core.intel.attack_feed import AttackFeed, parse_stix
from redteam_core.intel.atlas_feed import AtlasFeed
from redteam_core.intel.catalog import arsenal_techniques, build_catalog, coverage, lookup
from redteam_core.intel.feed_base import fetch_with_retry
from redteam_core.intel.kev_feed import KevFeed


# ============================ feed_base =====================================
def test_fetch_rejects_non_https():
    with pytest.raises(ValueError):
        fetch_with_retry("http://insecure.example/attack.json")


# ============================ 오프라인 시드 ================================
def test_attack_feed_offline_seed():
    snap = AttackFeed().fetch(offline=True)
    assert snap.fetched_via == "seed"
    assert snap.count > 0
    assert any(r["id"] == "T1692.001" for r in snap.records)
    # 결정론: 같은 시드 → 같은 sha256
    assert snap.sha256 == AttackFeed().fetch(offline=True).sha256

def test_atlas_and_kev_offline():
    atlas = AtlasFeed().fetch(offline=True)
    kev = KevFeed().fetch(offline=True)
    assert any(r["id"].startswith("AML.T") for r in atlas.records)
    assert all("cve" in r for r in kev.records)


# ============================ 라이브 폴백 ==================================
def test_live_failure_falls_back_to_seed(monkeypatch):
    import redteam_core.intel.attack_feed as af
    monkeypatch.setattr(af, "fetch_with_retry",
                        lambda url, **kw: (_ for _ in ()).throw(RuntimeError("net down")))
    snap = AttackFeed().fetch(offline=False)             # 라이브 실패 → 시드 폴백
    assert snap.fetched_via == "seed"
    assert snap.count > 0


# ============================ STIX 파서 ====================================
def test_parse_stix_extracts_technique():
    bundle = (b'{"objects":[{"type":"attack-pattern","name":"Test T",'
              b'"external_references":[{"source_name":"mitre-ics-attack","external_id":"T9999"}],'
              b'"kill_chain_phases":[{"kill_chain_name":"mitre-ics-attack","phase_name":"impact"}]},'
              b'{"type":"attack-pattern","revoked":true,'
              b'"external_references":[{"source_name":"mitre-ics-attack","external_id":"T0001"}]}]}')
    recs = parse_stix(bundle)
    assert recs == [{"id": "T9999", "name": "Test T", "tactics": ["impact"]}]  # revoked 제외


# ============================ 커버리지 =====================================
def test_coverage_covered_and_gaps():
    cov = coverage(offline=True)
    assert "T1692.001" in cov["covered"]                 # 무기고 ∩ 카탈로그
    # 능력 확장(ML+ICS) 후 무기고가 카탈로그를 전부 커버 → coverage_pct==1.0.
    assert cov["coverage_pct"] == 1.0
    # 단 AML.T0020(공급망 poisoning)은 런타임 미검증 스테이징 → 런타임 커버리지는 <1.0.
    assert cov["runtime_coverage_pct"] < 1.0
    assert cov["staged"] == ["AML.T0020"] and not cov["gaps"]

def test_arsenal_from_mapping():
    arsenal = arsenal_techniques()
    assert "T0835" in arsenal and "T1106" in arsenal

def test_lookup_offline():
    assert lookup("T1692.001", offline=True)["name"]
    assert lookup("NOPE-000", offline=True) is None

def test_build_catalog_three_sources():
    cat = build_catalog(offline=True)
    assert set(cat) == {"attack", "atlas", "kev"}
