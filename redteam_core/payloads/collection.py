"""수동 수집·심화 정찰 — red 실 능력 (S63~S64, §N).

팀 UAV 매트릭스가 ❌(탐지불가)로 둔 기법 중 'blue 미탐지'일 뿐 'red 실행 가능'인
것들을 실 능력으로 구현. red 가 수행 O, blue 로그 없음 → blind_spot(방어 공백).
이는 커버리지를 정직하게 늘림(분모 재정의 아님). 결정론·무의존.

- S63 수동 수집: 영상/화면/로컬파일/키입력/자동수집/프로그램추출
- S64 심화 정찰: 네트워크 구조 수집 / 공개 CVE DB 검색
"""
from __future__ import annotations

from .exploits import ExploitPayload


# ── S63 수동 수집 (Collection, blue 로그 없음) ───────────────────────────────
def craft_video_capture() -> ExploitPayload:
    return ExploitPayload("S63", "collection", {"src": "EO/IR downlink", "mode": "passive tap"},
                          "T1125", "평문 영상 다운링크 수동 도청")


def craft_automated_collection() -> ExploitPayload:
    return ExploitPayload("S63", "collection", {"src": "imagery+SAR", "auto": True, "uav_ids": "다수"},
                          "T1119", "다수 UAVId 영상·SAR 프레임 자동 도청")


def craft_program_upload() -> ExploitPayload:
    return ExploitPayload("S63", "collection", {"op": "MISSION_REQUEST_LIST/PARAM_REQUEST_READ"},
                          "T0845", "MAVLink 로 임무/파라미터 추출(읽기)")


def craft_screen_capture() -> ExploitPayload:
    return ExploitPayload("S63", "collection", {"src": "noVNC/QGC :8080 콘솔"},
                          "T1113", "QGC 콘솔 화면 캡처")


def craft_local_data() -> ExploitPayload:
    return ExploitPayload("S63", "collection", {"path": "/opt/uav/{mission,logs,sar}"},
                          "T1005", "컨테이너 로컬 파일(임무·로그·SAR) 읽기")


def craft_input_capture() -> ExploitPayload:
    return ExploitPayload("S63", "collection", {"src": "GCS 콘솔 keystroke"},
                          "T1056", "GCS 명령 입력 가로채기")


# ── S64 심화 정찰 (Reconnaissance) ───────────────────────────────────────────
def craft_network_recon() -> ExploitPayload:
    return ExploitPayload("S64", "recon", {"scope": "GCS↔datalink↔AV 토폴로지", "method": "conn enum"},
                          "T1590", "네트워크 구조·통신경로 수집")


def craft_cve_search() -> ExploitPayload:
    return ExploitPayload("S64", "recon", {"db": "ArduPilot/QGC CVE", "via": "§Q cve_intel"},
                          "T1596", "공개 기술 DB(CVE) 검색으로 취약점 후보 확보")


COLLECTION_SCENARIOS = {
    "T1125": craft_video_capture, "T1119": craft_automated_collection,
    "T0845": craft_program_upload, "T1113": craft_screen_capture,
    "T1005": craft_local_data, "T1056": craft_input_capture,
    "T1590": craft_network_recon, "T1596": craft_cve_search,
}
