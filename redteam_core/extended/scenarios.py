"""빈 번호 채움 시나리오 정의 — S22·S28·S63~S65·S74~S85 (17개).

각 시나리오: objective(에이전트 배선용)·이름·MITRE·테마. 전부 사각지대(모델).
"""
from __future__ import annotations

from dataclasses import dataclass

# sid → (objective, 이름, MITRE, 테마)
EXTENDED_SCENARIOS = {
    # ── 공중 세그먼트 원본 보강 ──
    "S22": ("param_mass_reset", "파라미터 대량 리셋/공장초기화(failsafe 무력화)", "T0836", "공중"),
    "S28": ("video_downlink_inject", "EO/IR 영상 다운링크 감청·프레임 주입", "T1557", "공중"),
    # ── 수동 정찰·수집(평문·미기록) ──
    "S63": ("passive_telemetry_sniff", "수동 텔레메트리 감청(평문 링크)", "T0887", "정찰"),
    "S64": ("passive_asset_enum", "수동 자산·네트워크 열거", "T0840", "정찰"),
    # ── 기체/전원/페이로드 ──
    "S65": ("bms_power_spoof", "배터리/전원(BMS) 스푸핑→조기 RTL/착륙", "T0836", "기체"),
    "S74": ("gimbal_hijack", "짐벌/페이로드 제어 하이재킹(센서 지향 조작)", "T0831", "기체"),
    # ── 공급망 / DevSecOps (S4·S53~55 확장) ──
    "S75": ("registry_image_tamper", "컨테이너 레지스트리 이미지 변조", "T1195.002", "공급망"),
    "S76": ("cicd_pipeline_compromise", "CI/CD 파이프라인 침해", "T1195.001", "공급망"),
    "S77": ("secrets_vault_theft", "시크릿/키 관리(Vault) 탈취", "T1552", "공급망"),
    "S78": ("mtls_cert_forge", "mTLS 인증서 위조", "T1649", "공급망"),
    "S79": ("dependency_confusion", "의존성 혼동(dependency confusion)", "T1195.001", "공급망"),
    "S80": ("iac_tamper", "IaC(Terraform/Helm) 변조", "T1195", "공급망"),
    "S81": ("artifact_signing_bypass", "아티팩트 서명 우회", "T1553", "공급망"),
    "S82": ("build_provenance_attack", "빌드 프로버넌스/재현성 무결성 공격", "T1195", "공급망"),
    # ── 메시징/미들웨어 ──
    "S83": ("dds_discovery_flood", "DDS/ROS2 discovery 플러딩", "T1499", "미들웨어"),
    "S84": ("mqtt_bus_poison", "MQTT/메시지버스 텔레메트리 오염", "T1565.001", "미들웨어"),
    "S85": ("geofence_tamper", "지리펜스(geofence) 변조·우회", "T0839", "미들웨어"),
}


@dataclass
class ExtResult:
    scenario: str
    objective: str
    name: str
    mitre: str
    theme: str
    note: str = "blue 전용 탐지룰 미배포 = 사각지대(모델 판정)"


def run_extended(scenario_id: str) -> ExtResult:
    obj, name, mitre, theme = EXTENDED_SCENARIOS[scenario_id]
    return ExtResult(scenario_id, obj, name, mitre, theme)


def themes() -> dict:
    out = {}
    for sid, (_o, _n, _m, theme) in EXTENDED_SCENARIOS.items():
        out.setdefault(theme, []).append(sid)
    return out
