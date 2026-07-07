"""(mapping) 공격 → ATT&CK-ICS → 예상 UAV*_CL 로그 → D3FEND (Part 3).

**독립성 유지:** 본 에이전트는 SOC와 코드 결합하지 않는다. 이 표가 유일한 다리 —
각 원자 액션이 예상 탐지 시그니처(SOC `UAV*_CL` 테이블)와 D3FEND 처방을 동반한다.
Reporter가 이 표로 "탐지격차 → 방어 산물"을 산출(공격→방어 distillation 2602.02595).

컬럼명은 Sentinel 스키마(PascalCase, `uav/sentinel-schemas.md`) 기준.
D3FEND v1.4.0: ※ D3-ET는 재검증에서 Harden→**Isolate**로 정정.
"""

from __future__ import annotations

# action -> {attack_ics, expected_logs, d3fend, blind_spot}
# blind_spot=True면 D3FEND Detect 미커버 → 탐지격차 1순위(§1.8).
MAP = {
    "recon_heartbeat": {
        "attack_ics": ["T0840"],
        "expected_logs": ["UAVDatalinkConn_CL LocalPort=5790 PeerIp∉known"],
        "d3fend": ["Isolate D3-NI(5790 격리)", "Detect D3-NTA"],
        "blind_spot": False,
    },
    "set_mode": {
        "attack_ics": ["T1692.001"],
        "expected_logs": ["UAVOperator_CL Command=176 SourceSystemId∉{1,254,255}",
                          "UAVTelemetry_CL CustomMode 델타"],
        "d3fend": ["Harden D3-MAN(MAVLink2 서명)", "Isolate D3-CF", "Detect D3-NTA"],
        "blind_spot": False,
    },
    "force_arm": {
        "attack_ics": ["T1692.001", "T1106"],
        "expected_logs": ["UAVOperator_CL SourceSystemId∉{1,254,255} Command=400 Param1=1"],
        "d3fend": ["Harden D3-MAN(MAVLink2 서명)", "Isolate D3-CF", "Detect D3-NTA"],
        "blind_spot": False,
    },
    "param_set_safety": {
        "attack_ics": ["T0836", "T0838"],
        "expected_logs": ["UAVConfigAudit_CL ParamId=ARMING_CHECK/FS_* ParamValueAfter=0"],
        "d3fend": ["Harden D3-ACH(파라미터)", "D3-MAN", "Isolate D3-APA"],
        "blind_spot": False,
    },
    "mission_upload": {
        "attack_ics": ["T0821"],
        "expected_logs": ["UAVMissionEvent_CL 비정상 Seq", "UAVConfigAudit_CL ParamValueAfter"],
        "d3fend": ["Harden D3-ACH", "Harden D3-MAN(서명 임무)"],
        "blind_spot": False,
    },
    "takeoff": {
        "attack_ics": ["T1692.001"],
        "expected_logs": ["UAVTelemetry_CL SystemStatus 급변", "UAVFailsafe_CL ModeAfter"],
        "d3fend": ["Harden D3-MAN", "Isolate D3-APA(2인통제)", "Harden D3-ACH"],
        "blind_spot": False,
    },
    "disarm": {
        "attack_ics": ["T0831", "T0827"],
        "expected_logs": ["UAVFailsafe_CL ModeAfter", "UAVTelemetry_CL SystemStatus 급변"],
        "d3fend": ["Harden D3-MAN", "Isolate D3-APA(2인통제)", "Harden D3-ACH"],
        "blind_spot": False,
    },
    "flight_terminate": {
        "attack_ics": ["T0831", "T0880"],
        "expected_logs": ["UAVFailsafe_CL ModeAfter", "UAVTelemetry_CL SystemStatus 급변"],
        "d3fend": ["Isolate D3-APA(2인통제)", "Harden D3-MAN"],
        "blind_spot": False,
    },
    "gnss_spoof": {
        "attack_ics": ["T0835", "T0832"],
        "expected_logs": ["UAVTelemetry_CL PosHorizVariance>0.5 VelocityVariance↑ FixType↓"],
        "d3fend": ["D3FEND 미커버 → custom(다중센서 융합·항스푸핑)"],
        "blind_spot": True,     # RF/GNSS는 D3FEND 미커버 → 탐지격차 1순위(§1.8)
    },
    "jam": {
        "attack_ics": ["T0814"],
        "expected_logs": ["UAVDatalink_CL RxDropped 델타↑", "UAVSatcomLink_CL JamIndicator↑"],
        "d3fend": ["D3FEND 미커버 → custom(항재밍·링크 다중화)", "Isolate D3-NI"],
        "blind_spot": True,
    },
    "satcom_mitm": {
        "attack_ics": ["T0830", "T0831"],
        "expected_logs": ["UAVSatcomLink_CL IntegrityStatus≠ok Seq점프 SessionId급변"],
        "d3fend": ["Harden D3-MAN·D3-MENCR", "Isolate D3-ET(링크 암호화/터널)"],
        "blind_spot": False,
    },
    # --- 온보드-AI 평면(ATLAS AML) — attack_ics 컬럼에 AML ID를 실어 무기고에 편입 ----
    # SOC UAV*_CL 스키마는 물리 텔레메트리 중심 → 온보드 AI 이벤트는 대부분 미관측(사각지대).
    "ml_craft_adversarial": {
        "attack_ics": ["AML.T0043"],
        "expected_logs": ["(오프라인 스테이징 — 표적 텔레메트리 흔적 없음)"],
        "d3fend": ["D3FEND 미커버 → custom(적대적 견고성 훈련·입력 검증)"],
        "blind_spot": True,     # 스테이징은 표적 밖 → 탐지 불가
    },
    "ml_evade_perception": {
        "attack_ics": ["AML.T0015"],
        "expected_logs": ["UAVPerception_CL DetectConfidence급락/ClassFlip (스키마 부재 시 미관측)"],
        "d3fend": ["D3FEND 미커버 → custom(적대적 견고 모델·다중센서 교차검증·OOD 탐지)"],
        "blind_spot": True,     # 온보드 인지모델 → SOC 미관측 → 탐지격차 1순위
    },
    "ml_prompt_inject": {
        "attack_ics": ["AML.T0051"],
        "expected_logs": ["UAVAgentAudit_CL 지시-데이터 경계위반/툴콜 이상 (스키마 부재 시 미관측)"],
        "d3fend": ["D3FEND 미커버 → custom(지시/데이터 분리·구분자 격리·출력 제약)"],
        "blind_spot": True,     # 우리 C 하드닝의 공격판 — 표적 코파일럿엔 방어 부재 가정
    },
    "ml_extract_secret": {
        "attack_ics": ["AML.T0057"],
        "expected_logs": ["UAVAgentAudit_CL 시크릿 패턴 출력/비정상 exfil (스키마 부재 시 미관측)"],
        "d3fend": ["D3FEND 미커버 → custom(출력 필터·시크릿 스코핑·최소권한 컨텍스트)"],
        "blind_spot": True,
    },
    "ml_poison_training": {
        "attack_ics": ["AML.T0020"],
        "expected_logs": ["(오프라인 공급망 — 런타임 표적 텔레메트리 없음; 스테이징 전용)"],
        "d3fend": ["D3FEND 미커버 → custom(데이터 출처 검증·훈련 파이프라인 무결성·모델 서명)"],
        "blind_spot": True,     # 오프라인 공급망 → 런타임 탐지 표면 없음(스테이징 능력)
    },
    # --- 잔여 ATT&CK-ICS 평면 -------------------------------------------------
    "active_scan": {
        "attack_ics": ["T1595"],
        "expected_logs": ["UAVDatalinkConn_CL 다중 포트 probe PeerIp∉known ShortInterval"],
        "d3fend": ["Detect D3-NTA(스캔 탐지)", "Isolate D3-NI(포트 격리)"],
        "blind_spot": False,
    },
    "c2_common_port": {
        "attack_ics": ["T0885"],
        "expected_logs": ["UAVDatalinkConn_CL LocalPort=5790 지속세션 PeerIp∉known"],
        "d3fend": ["Detect D3-NTA(트래픽 분석)", "Isolate D3-NI(망분리·상용포트 정책)"],
        "blind_spot": False,
    },
    "unauthorized_command": {
        "attack_ics": ["T0855"],
        "expected_logs": ["UAVOperator_CL SourceSystemId∉{1,254,255} 무인가 Command"],
        "d3fend": ["Harden D3-MAN(MAVLink2 서명)", "Isolate D3-CF", "Detect D3-NTA"],
        "blind_spot": False,
    },
    "spoof_telemetry": {
        "attack_ics": ["T0856"],
        "expected_logs": ["UAVTelemetry_CL 보고값 vs 지상계측 불일치 (서명 부재 시 미검출)"],
        "d3fend": ["Harden D3-MAN(서명 텔레메트리)", "custom(지상계측 교차검증)"],
        "blind_spot": True,     # 보고 위조는 서명 없으면 탐지난망 → 탐지격차
    },
    "disable_protection": {
        "attack_ics": ["T0837"],
        "expected_logs": ["UAVConfigAudit_CL ParamId=FS_*/GEOFENCE ParamValueAfter=0"],
        "d3fend": ["Harden D3-ACH(파라미터 잠금)", "Harden D3-MAN", "Isolate D3-APA"],
        "blind_spot": False,
    },
}


def lookup(action: str) -> dict:
    return dict(MAP.get(action, {"attack_ics": [], "expected_logs": [],
                                 "d3fend": [], "blind_spot": False}))
