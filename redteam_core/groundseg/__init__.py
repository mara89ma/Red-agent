"""groundseg — 지상 세그먼트 소프트웨어 공격 (공격면 도메인).

UAV 기체(공중 세그먼트) 외 **지상/클라우드 소프트웨어** 공격면. 4요소:
  - GCS 애플리케이션 S72~S75 (QGC/Mission Planner)
  - 컴패니언/ROS       S76~S78 (온보드 Linux·ROS/MAVROS)
  - 지상 인프라/데이터링크 S79~S81 (모뎀·SATCOM·GDT)
  - 함대/클라우드 백엔드   S82~S85 (함대API·영상스트림·C4I)

발견: UAV Sentinel(blue)은 텔레메트리/공중 평면만 감시 → 지상 소프트웨어 = 사각지대.
안전: 아티팩트만(dry). 실 공격은 표적 env + §T 샌드박스 통과 시에만.
"""
from .attacks import GROUND_SCENARIOS, build_artifact, run_ground, surfaces

__all__ = ["GROUND_SCENARIOS", "build_artifact", "run_ground", "surfaces"]
