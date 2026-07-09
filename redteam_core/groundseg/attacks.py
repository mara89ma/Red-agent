"""지상 세그먼트 공격 — GCS 앱·ROS·데이터링크·클라우드 (S72~S85).

각 시나리오는 실 공격 아티팩트(악성 미션파일·ROS pub·RTSP 요청 등)를 생성한다.
UAV Sentinel 미감시 계층 = 사각지대. 실 실행은 표적 env + §T 샌드박스.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

# surface: gcs | ros | datalink | cloud
GROUND_SCENARIOS = {
    # ── GCS 애플리케이션 (QGroundControl/Mission Planner) ──
    "S72": {"surface": "gcs", "name": "악성 미션파일 파싱 익스플로잇", "objective": "gcs_mission_parse",
            "mitre": "T1203", "kind": "mission_file"},
    "S73": {"surface": "gcs", "name": "QML/플러그인 인젝션", "objective": "gcs_plugin_inject",
            "mitre": "T1059", "kind": "qml"},
    "S74": {"surface": "gcs", "name": "GCS 자동업데이트 MITM", "objective": "gcs_update_mitm",
            "mitre": "T1195.002", "kind": "update"},
    "S75": {"surface": "gcs", "name": "GCS 설정/로그 변조", "objective": "gcs_config_tamper",
            "mitre": "T1565", "kind": "config"},
    # ── 컴패니언 컴퓨터 / ROS ──
    "S76": {"surface": "ros", "name": "무인증 ROS 마스터 접근", "objective": "ros_master_access",
            "mitre": "T1190", "kind": "ros_master"},
    "S77": {"surface": "ros", "name": "ROS 토픽/서비스 인젝션", "objective": "ros_topic_inject",
            "mitre": "T0855", "kind": "ros_pub"},
    "S78": {"surface": "ros", "name": "MAVROS 명령 주입", "objective": "mavros_cmd_inject",
            "mitre": "T0831", "kind": "ros_pub"},
    # ── 지상 인프라 / 데이터링크 ──
    "S79": {"surface": "datalink", "name": "모뎀/SATCOM 터미널 펌웨어", "objective": "modem_firmware",
            "mitre": "T0857", "kind": "firmware"},
    "S80": {"surface": "datalink", "name": "텔레메트리 릴레이 MITM", "objective": "telemetry_relay_mitm",
            "mitre": "T1557", "kind": "mitm"},
    "S81": {"surface": "datalink", "name": "GDT NTP 타임서버 스푸핑", "objective": "gdt_ntp_spoof",
            "mitre": "T1195", "kind": "ntp"},
    # ── 함대 / 클라우드 백엔드 ──
    "S82": {"surface": "cloud", "name": "함대관리 API 인증우회", "objective": "fleet_api_bypass",
            "mitre": "T1190", "kind": "http"},
    "S83": {"surface": "cloud", "name": "텔레메트리 수집 오염", "objective": "telemetry_poison",
            "mitre": "T1565.001", "kind": "http"},
    "S84": {"surface": "cloud", "name": "영상스트림 RTSP 하이재킹", "objective": "video_stream_hijack",
            "mitre": "T1557", "kind": "rtsp"},
    "S85": {"surface": "cloud", "name": "C4I 메시지 주입", "objective": "c4i_inject",
            "mitre": "T1565", "kind": "http"},
}

_SURFACE_LABEL = {"gcs": "GCS 애플리케이션", "ros": "컴패니언/ROS",
                  "datalink": "지상 인프라/데이터링크", "cloud": "함대/클라우드 백엔드"}


@dataclass
class GroundResult:
    scenario: str
    surface: str
    artifact: str
    transmitted: bool
    note: str = ""


def build_artifact(scenario_id: str) -> str:
    """시나리오별 실 공격 아티팩트(요지) 생성."""
    m = GROUND_SCENARIOS[scenario_id]
    k = m["kind"]
    if k == "mission_file":     # 경로순회/오버플로 유발 .plan
        return "malicious .plan traversal=" + "../" * 8 + "etc/passwd (파서 오버플로)"
    if k == "qml":
        return "QML inject: import Qt; Component.onCompleted: exec('rt')"
    if k == "update":
        return "update MITM: rogue appcast + unsigned binary"
    if k == "config":
        return "config tamper: MAVLINK_COMM 재지정·로그 삭제"
    if k == "ros_master":
        return "ROS master: rosnode list @ 11311 (무인증)"
    if k == "ros_pub":
        topic = "/mavros/setpoint_velocity/cmd_vel" if m["objective"].startswith("mavros") else "/cmd_vel"
        return f"rostopic pub {topic} (위조 명령)"
    if k == "firmware":
        return "modem firmware: unsigned OTA image"
    if k == "mitm":
        return "telemetry relay MITM: MAVLink 프레임 변조 프록시"
    if k == "ntp":
        return "NTP spoof: 시각 오프셋 주입(로그 상관 교란·인증 만료)"
    if k == "rtsp":
        return "RTSP hijack: DESCRIBE/PLAY 세션 탈취·프레임 주입"
    return "HTTP: " + {"fleet_api_bypass": "GET /api/fleet/{id} IDOR",
                       "telemetry_poison": "POST /ingest 위조 텔레메트리",
                       "c4i_inject": "POST /c4i/order 위조 명령"}.get(m["objective"], "POST")


def run_ground(scenario_id: str, dry: bool = True) -> GroundResult:
    m = GROUND_SCENARIOS[scenario_id]
    art = build_artifact(scenario_id)
    sent = False
    if not dry:
        from ..sandbox import guarded
        r = guarded({"name": f"ground:{scenario_id}", "network": []}, lambda: {"sent": True})
        sent = "sent" in r
    return GroundResult(scenario_id, m["surface"], art, sent,
                        "UAV Sentinel 미감시 계층=사각지대. 실 실행=표적 env+§T 샌드박스")


def surfaces() -> dict:
    """공격면별 시나리오 그룹."""
    out = {}
    for sid, m in GROUND_SCENARIOS.items():
        out.setdefault(m["surface"], {"label": _SURFACE_LABEL[m["surface"]], "scenarios": []})
        out[m["surface"]]["scenarios"].append(sid)
    return out
