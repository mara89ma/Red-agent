"""지상 세그먼트 공격 테스트 — GCS·ROS·데이터링크·클라우드. 결정론·무의존."""
from __future__ import annotations

from redteam_core.assessment import OBJECTIVES, adaptive_engage
from redteam_core.campaigns import run_chain
from redteam_core.groundseg import GROUND_SCENARIOS, build_artifact, run_ground, surfaces


def test_scenarios_span_four_surfaces():
    assert set(surfaces()) == {"gcs", "ros", "datalink", "cloud"}
    assert set(GROUND_SCENARIOS) == {f"S{n}" for n in range(72, 86)}


def test_objectives_registered():
    for m in GROUND_SCENARIOS.values():
        assert m["objective"] in OBJECTIVES


def test_artifacts_built_per_surface():
    assert "passwd" in build_artifact("S72")          # 경로순회 미션파일
    assert "rostopic pub" in build_artifact("S78")    # MAVROS 주입
    assert "RTSP" in build_artifact("S84")            # 영상 하이재킹
    assert "IDOR" in build_artifact("S82")            # 함대 API


def test_ground_is_sentinel_blindspot():
    # 지상 세그먼트는 UAV Sentinel 미감시 → 전부 사각지대 은밀 달성.
    for sid in ("S72", "S76", "S80", "S85"):
        obj = GROUND_SCENARIOS[sid]["objective"]
        r = adaptive_engage(obj)
        assert r.verdict == "achieved" and r.trace[-1][2].detected is None


def test_ground_killchains_stealthy():
    for cid in ("C19", "C20"):
        assert run_chain(cid).verdict == "stealthy"   # 전 단계 사각 → 은밀 관통


def test_dry_no_transmission():
    assert run_ground("S72", dry=True).transmitted is False
