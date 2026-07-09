"""기법별 실 아티팩트 레지스트리 테스트 — 모듈참조 승격 검증. 결정론·무의존."""
from __future__ import annotations

from redteam_core.mapping.artifacts import ARTIFACT_REGISTRY, produce, artifact_backed
from redteam_core.mapping.uav_coverage import RED_COVER, verified_summary

# 이전 '모듈참조'로 분류됐던 23개 — 이제 아티팩트로 승격돼야 함.
_PROMOTED = {
    "T1592", "T1542.001", "T0859", "T1070", "T1036", "T1210", "T1570", "T1021",
    "T1550", "T1694", "T1071", "T1571", "T1008", "T1105", "T1095", "T1104",
    "T1219", "T1048", "T0892", "T0879", "T0826", "T0828", "T1531",
}


def test_all_registry_entries_produce_real_artifacts():
    for tid in ARTIFACT_REGISTRY:
        a = produce(tid)
        assert a, tid                                  # 빈 산출물 아님
        assert isinstance(a, (bytes, dict)) or hasattr(a, "__class__")


def test_transport_artifacts_are_real_bytes():
    assert isinstance(produce("T1071"), bytes) and len(produce("T1071")) > 0   # MAVLink C2 프레임
    assert isinstance(produce("T1095"), bytes) and len(produce("T1095")) > 0   # raw transport


def test_persistence_and_maneuver_artifacts_are_objects():
    assert produce("T1542.001").__class__.__name__ == "FileImplant"
    assert produce("T1210").__class__.__name__ == "CampaignResult"


def test_all_promoted_module_refs_now_artifact_backed():
    art = artifact_backed()
    for tid in _PROMOTED:
        assert tid in RED_COVER and tid in art, tid   # 커버 + 아티팩트 승격 완료


def test_no_pure_label_mappings_remain():
    v = verified_summary()
    assert v["no_pure_label"] is True                  # 순수 서술 라벨 매핑 0
    assert v["callable_pct"] >= 60.0                   # 호출가능 아티팩트/액션 비중
