"""UAV ATT&CK 커버리지 매트릭스 — 팀 UAV 매트릭스(15전술·111기법) 대비 RED 커버리지.

동언님·수지님이 만든 'UAV ATT&CK 매핑표(Enterprise+ICS)'를 기준선으로, 우리 RED
에이전트(S1~S55 + 액션/모듈)가 각 기법을 실제로 공격하는지 매핑한다. 산출:
per-tactic 커버리지·갭(미커버 기법)·히어로셋(blue 탐지불가 ❌ 기법 중 우리가 공격).

detectable=False(❌) = blue Sentinel 로그/룰로 탐지 불가 기법 → 우리가 커버하면
'은밀 공격'으로 최고 가치(방어 공백 실증). 결정론·무의존.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# (전술, 기법ID, 짧은 이름, blue 탐지가능?) — 팀 UAV 매트릭스 그대로.
UAV_MATRIX: List[Tuple[str, str, str, bool]] = [
    ("Reconnaissance", "T1595", "Active Scanning", True),
    ("Reconnaissance", "T1592", "Gather Host Info", True),
    ("Reconnaissance", "T1590", "Gather Network Info", False),
    ("Reconnaissance", "T1596", "Search Open Tech DB", False),
    ("Resource Dev", "T1587", "Develop Capabilities", False),
    ("Resource Dev", "T1588", "Obtain Capabilities", False),
    ("Resource Dev", "T1608", "Stage Capabilities", False),
    ("Initial Access", "T1190", "Exploit Public App", True),
    ("Initial Access", "T1133", "External Remote Services", True),
    ("Initial Access", "T1195", "Supply Chain Compromise", True),
    ("Initial Access", "T1078", "Valid Accounts", True),
    ("Initial Access", "T0860", "Wireless Compromise", True),
    ("Initial Access", "T0864", "Transient Cyber Asset", True),
    ("Execution", "T1059", "Command/Scripting", True),
    ("Execution", "T1106", "Native API", True),
    ("Execution", "T1204", "User Execution", True),
    ("Execution", "T0821", "Modify Controller Tasking", True),
    ("Execution", "T1692.001", "Unauthorized Message", True),
    ("Persistence", "T1556", "Modify Auth Process", True),
    ("Persistence", "T1542.001", "Modify Firmware", True),
    ("Persistence", "T0859", "Valid Accounts (backdoor)", True),
    ("Persistence", "T1546", "Event Triggered Exec", True),
    ("Privilege Escalation", "T1068", "Exploit for Priv Esc", True),
    ("Privilege Escalation", "T1078.pe", "Valid Accounts (high-priv)", True),
    ("Stealth/Evasion", "T1070", "Indicator Removal", True),
    ("Stealth/Evasion", "T1036", "Masquerading", True),
    ("Stealth/Evasion", "T1601", "Modify System Image", True),
    ("Stealth/Evasion", "T1014", "Rootkit", False),
    ("Stealth/Evasion", "T0878", "Alarm Suppression", True),
    ("Discovery", "T0840", "Network Conn Enum", True),
    ("Discovery", "T0842", "Network Sniffing", True),
    ("Discovery", "T0887", "Wireless Sniffing", True),
    ("Lateral Movement", "T0843", "Program Download", True),
    ("Lateral Movement", "T1210", "Exploit Remote Services", True),
    ("Lateral Movement", "T1563", "Remote Session Hijack", True),
    ("Lateral Movement", "T1570", "Lateral Tool Transfer", True),
    ("Lateral Movement", "T1021", "Remote Services", True),
    ("Lateral Movement", "T1550", "Alt Auth Material", True),
    ("Lateral Movement", "T1694", "Insecure Credentials", True),
    ("Lateral Movement", "T1080", "Taint Shared Content", True),
    ("Collection", "T1557", "Adversary-in-the-Middle", True),
    ("Collection", "T1125", "Video Capture", False),
    ("Collection", "T1119", "Automated Collection", False),
    ("Collection", "T0845", "Program Upload", False),
    ("Collection", "T1113", "Screen Capture", False),
    ("Collection", "T1185", "Browser Session Hijack", True),
    ("Collection", "T1005", "Data from Local System", False),
    ("Collection", "T1056", "Input Capture", False),
    ("Collection", "T1074", "Data Staged", False),
    ("Collection", "T1560", "Archive Collected Data", False),
    ("Command and Control", "T1071", "App Layer Protocol", True),
    ("Command and Control", "T1571", "Non-Standard Port", True),
    ("Command and Control", "T1090", "Proxy", True),
    ("Command and Control", "T1008", "Fallback Channels", True),
    ("Command and Control", "T1659", "Content Injection", True),
    ("Command and Control", "T1105", "Ingress Tool Transfer", True),
    ("Command and Control", "T1095", "Non-App Layer Protocol", True),
    ("Command and Control", "T1572", "Protocol Tunneling", False),
    ("Command and Control", "T1104", "Multi-Stage Channels", True),
    ("Command and Control", "T1573", "Encrypted Channel", False),
    ("Command and Control", "T1219", "Remote Access Tools", True),
    ("Command and Control", "T1001", "Data Obfuscation", False),
    ("Command and Control", "T1132", "Data Encoding", False),
    ("Exfiltration", "T1041", "Exfil over C2", True),
    ("Exfiltration", "T1011", "Exfil over Other Medium", False),
    ("Exfiltration", "T1020", "Automated Exfil", True),
    ("Exfiltration", "T1029", "Scheduled Transfer", True),
    ("Exfiltration", "T1048", "Exfil over Alt Protocol", True),
    ("Exfiltration", "T1030", "Data Transfer Size Limits", True),
    ("Exfiltration", "T1567", "Exfil over Web Service", False),
    ("Impair Process Control", "T0836", "Modify Parameter", True),
    ("Impair Process Control", "T1693", "Modify Firmware (FCC)", True),
    ("Impair Process Control", "T1692", "Unauthorized Message", True),
    ("Impair Process Control", "T0806", "Brute Force I/O", True),
    ("Inhibit Response", "T0838", "Modify Alarm Settings", True),
    ("Inhibit Response", "T0814", "Denial of Service", True),
    ("Inhibit Response", "T1695", "Block Communications", True),
    ("Inhibit Response", "T1691.002", "Block Reporting Message", True),
    ("Inhibit Response", "T0881", "Service Stop", True),
    ("Inhibit Response", "T0816", "Device Restart/Shutdown", True),
    ("Inhibit Response", "T0892", "Change Credential", True),
    ("Inhibit Response", "T0835", "Manipulate I/O Image", True),
    ("Inhibit Response", "T0809", "Data Destruction", False),
    ("Inhibit Response", "T0800", "Activate FW Update Mode", False),
    ("Inhibit Response", "T0851", "Rootkit (Inhibit)", False),
    ("Impact", "T0832", "Manipulation of View", True),
    ("Impact", "T0882", "Theft of Op Info", False),
    ("Impact", "T0827", "Loss of Control", True),
    ("Impact", "T0880", "Loss of Safety", True),
    ("Impact", "T0879", "Damage to Property", True),
    ("Impact", "T1498", "Network DoS", True),
    ("Impact", "T1565", "Data Manipulation", True),
    ("Impact", "T0815", "Denial of View", True),
    ("Impact", "T0831", "Manipulation of Control", True),
    ("Impact", "T0813", "Denial of Control", True),
    ("Impact", "T0829", "Loss of View", True),
    ("Impact", "T0826", "Loss of Availability", True),
    ("Impact", "T0837", "Loss of Protection", True),
    ("Impact", "T0828", "Loss of Productivity", True),
    ("Impact", "T1499", "Endpoint DoS", True),
    ("Impact", "T1529", "System Shutdown/Reboot", True),
    ("Impact", "T1495", "Firmware Corruption", True),
    ("Impact", "T1485", "Data Destruction", False),
    ("Impact", "T1531", "Account Access Removal", True),
    # ── UAV 특화 신규 기법(§V WiFi·§W RC/모터·§Z 센서가 사용하나 팀 매트릭스에 없던 것) ──
    ("Impair Process Control", "T0855", "Unauthorized Command Message", False),
    ("Lateral Movement", "T1552", "Unsecured Credentials", False),
    ("Lateral Movement", "T1555", "Credentials from Password Stores", False),
    ("Stealth/Evasion", "T1600", "Weaken Encryption", False),
    ("Command and Control", "T1090.002", "External Proxy (위성 링크 C2, Turla)", False),
]

# 기법ID → 우리 RED 가 실제로 공격하는 시나리오/모듈. (미기재 = 갭)
RED_COVER: Dict[str, str] = {
    "T1595": "S34/S6 active_scan(§F recon)",
    "T1592": "recon 표적정보 수집(§F)",
    "T1190": "S49 웹셸·스텁 취약점(§N exploits)",
    "T1133": "S48 IDOR·noVNC/QGC 악용",
    "T1195": "S4/S53~S55 공급망·아카이브(§N archive)",
    "T1078": "S6/S48 자격증명 탈취",
    "T0860": "S30/S39~S42 무선 침해(§C/§V)",
    "T0864": "S21 정비 임플란트(§L)",
    "T1059": "S49 웹셸 명령실행",
    "T1106": "MAVLink API 직접 호출(§K)",
    "T1204": "S12 악성 미션·무장 유도",
    "T0821": "S5 파라미터 변조",
    "T1692.001": "S18 비인가 MAVLink 주입",
    "T1542.001": "§L FileImplant/펌웨어 백도어",
    "T0859": "백도어 계정(§L persistence)",
    "T1546": "S52 cron/조건부 실행(§N exploits)",
    "T1068": "S50 권한상승 익스플로잇(§N)",
    "T1078.pe": "S48/S6 고권한 계정 탈취",
    "T1036": "masquerade — 정상 GCS 위장(§H)",
    "T1601": "S13 사이버태세/시스템이미지 변조",
    "T0878": "S20 경보 억제(Failsafe)",
    "T0840": "네트워크 연결 열거(§G maneuver)",
    "T0842": "S18 MAVLink 스니핑",
    "T1210": "§G 원격서비스 익스플로잇",
    "T1563": "S3/VNC 세션 하이재킹",
    "T1570": "§G Lateral Tool Transfer",
    "T1021": "§G 컨테이너간 원격서비스 피벗",
    "T1550": "탈취 세션토큰 재사용(§G)",
    "T1694": "무인증 5790 발판(§G)",
    "T1080": "S14 TI/임무 오염(taint)",
    "T1557": "S3 SATCOM 중간자",
    "T1185": "S48/noVNC 세션 탈취",
    "T1074": "S37 스테이징 유출(§M)",
    "T1071": "§K MAVLink C2",
    "T1571": "§K 비표준 포트 C2 비콘",
    "T1090": "S26 mavlink-router 프록시",
    "T1008": "LOS/BLOS 폴백(§K)",
    "T1659": "S3 콘텐츠 주입",
    "T1105": "§K Ingress Tool Transfer",
    "T1095": "§K 원시 TCP/UDP 운반",
    "T1104": "다단계 채널(§K/§G)",
    "T1219": "MAVProxy/QGC 원격제어(§Q)",
    "T1041": "S17/S36 C2 채널 유출",
    "T1020": "S35 SAR 자동 유출",
    "T1029": "S37 주기 버스트 전송",
    "T1048": "대체 프로토콜 유출(§M)",
    "T1030": "S37 분할 유출(chunk)",
    "T0836": "S5 파라미터 변조",
    "T1693": "S4 펌웨어 변조",
    "T1692": "S18 위조 MAVLink",
    "T0806": "S11 Brute Force I/O(무장)",
    "T0838": "S19 Failsafe 임계 변조",
    "T0814": "S30/S31 재밍 DoS(§C)",
    "T1695": "S31 통신 차단(재밍)",
    "T1691.002": "S28 보고 메시지 차단",
    "T0881": "S23 서비스 중단",
    "T0816": "S25 컨테이너 재시작",
    "T0892": "자격 변경 잠금",
    "T0835": "S1 GNSS I/O 조작",
    "T0832": "S1 위조 텔레메트리(기만)",
    "T0827": "S30 통제 상실(JAM)",
    "T0880": "S19/S20 안전 상실",
    "T0879": "추락/강제착륙",
    "T1498": "S30 네트워크 재밍 DoS",
    "T1565": "S17 SAR 데이터 변조",
    "T0815": "S28 영상 상실",
    "T0831": "S1 통제 조작",
    "T0813": "S30 통제 거부(재밍)",
    "T0829": "S28 영상 스트림 지속 단절",
    "T0826": "장기 재밍 가용성 상실",
    "T0837": "Failsafe 무력화 보호 상실",
    "T0828": "임무 실패 성과 저하",
    "T1499": "S25 엔드포인트 DoS",
    "T1529": "S23 시스템 종료",
    "T1495": "S4 펌웨어 손상",
    "T1531": "계정 잠금/삭제",
    # 동언님 병렬 시나리오(§V WiFi·§W 고급)로 커버되는 기법 매핑 보정.
    "T0887": "S39~S42 WiFi RF 스니핑(§V)",
    "T1070": "S43~S47 anti-forensics 흔적 제거(§W)",
    "T0843": "S14 taint + §G 편대 전파(program download)",
    "T1560": "S37 스테이징 + §N 아카이브 번들(collected data)",
    # 신규 IT 계층(팀 매트릭스엔 없지만 우리가 추가) — S48~S55 는 위 T1190/T1068 등에 매핑됨.
    # 보강 구현(S65~S71) — 커버리지 최대화, 실 아티팩트로 구현.
    "T1572": "S65 C2 터널링(SATCOM 캡슐화, §K covert_c2)",
    "T1573": "S65 C2 암호채널(XOR, §K covert_c2)",
    "T1001": "S65 C2 난독(더미 인터리브, §K covert_c2)",
    "T1132": "S65 C2 인코딩(base64, §K covert_c2)",
    "T0809": "S66 데이터 파괴(§N advanced)",
    "T1485": "S66 데이터 파괴(§N advanced)",
    "T1014": "S67 rootkit(§N advanced)",
    "T0851": "S67 rootkit-inhibit(§N advanced)",
    "T0800": "S68 FW 업데이트 모드 강제(§N advanced)",
    "T1556": "S69 인증 프로세스 변조(§N advanced)",
    "T1011": "S70 유출-SATCOM 대체매체(§N advanced)",
    "T1567": "S70 유출-REST 웹서비스(§N advanced)",
    "T0882": "S71 작전정보 탈취(§N advanced)",
    # 수동 수집·심화 정찰 실 구현(S63~S64) — red 수행 O, blue 로그 없음(사각).
    "T1125": "S63 영상 수동 도청(§N collection)",
    "T1119": "S63 자동 수집(§N collection)",
    "T0845": "S63 임무/파라미터 추출(§N collection)",
    "T1113": "S63 화면 캡처(§N collection)",
    "T1005": "S63 로컬 파일 수집(§N collection)",
    "T1056": "S63 키입력 가로채기(§N collection)",
    "T1590": "S64 네트워크 구조 정찰(§N collection)",
    "T1596": "S64 CVE DB 검색(§Q cve_intel)",
    # UAV 특화 신규 기법 매핑(마이터 매트릭스 신규 반영).
    "T0855": "S44 RC override 명령 주입(§W)",
    "T1552": "S42 WiFi 기본 자격증명(§V)",
    "T1555": "S43 RC 링크 바인딩 자격 탈취(§W)",
    "T1600": "S45 RC 프로토콜 다운그레이드(§W)",
    # 신규 시나리오 S60~S62 (APT 에뮬레이션 도출).
    "T1090.002": "S60 위성 링크 C2 하이재킹(Turla, §N uav_novel)",
}

# 미매핑 시나리오를 기존 기법 라벨에 병기(시나리오 반영, 커버리지 % 불변).
for _tid, _extra in {
    "T1557": " / S40 WiFi Evil Twin(§V)",
    "T1498": " / S41 WiFi 재밍(§V)",
    "T0831": " / S46 DShot/ESC 모터 조작(§W) / S61 GNSS 스푸핑 나포(RQ-170)",
    "T0806": " / S56~S59 다중센서 폴트(§Z)",
    "T0835": " / S56~S59 센서 EKF 기만(§Z) / S62 EKF 협조 폴트",
}.items():
    if _tid in RED_COVER:
        RED_COVER[_tid] += _extra

# 미커버 기법 분류: 'excluded'=진짜 불가능(공격자 자기 인프라만).
# SOFT 제외(수동수집·정찰)는 S63~S64 로 실 구현해 커버로 전환 → 제외에서 제거.
GAP_SCOPE: Dict[str, str] = {
    # 공격자가 자기 컴퓨터에서 도구 개발·획득·스테이징 — sim 밖, red 불가(반박 불가).
    "T1587": "excluded", "T1588": "excluded", "T1608": "excluded",
}


@dataclass
class TacticCoverage:
    tactic: str
    total: int
    covered: int
    blind_total: int          # ❌(탐지불가) 기법 수
    blind_covered: int        # 그중 우리가 공격하는 수(=은밀 공격 가치)
    gaps: List[str] = field(default_factory=list)


def coverage_by_tactic() -> List[TacticCoverage]:
    order: List[str] = []
    agg: Dict[str, Dict] = {}
    for tactic, tid, _name, detectable in UAV_MATRIX:
        if tactic not in agg:
            agg[tactic] = {"total": 0, "covered": 0, "blind_total": 0,
                           "blind_covered": 0, "gaps": []}
            order.append(tactic)
        a = agg[tactic]
        a["total"] += 1
        hit = tid in RED_COVER
        if hit:
            a["covered"] += 1
        else:
            a["gaps"].append(tid)
        if not detectable:
            a["blind_total"] += 1
            if hit:
                a["blind_covered"] += 1
    return [TacticCoverage(t, agg[t]["total"], agg[t]["covered"], agg[t]["blind_total"],
                           agg[t]["blind_covered"], agg[t]["gaps"]) for t in order]


def summary() -> dict:
    total = len(UAV_MATRIX)
    covered = sum(1 for _, tid, _, _ in UAV_MATRIX if tid in RED_COVER)
    blind = [(tid, name) for _, tid, name, det in UAV_MATRIX if not det]
    blind_covered = [(tid, name) for tid, name in blind if tid in RED_COVER]
    return {
        "total_techniques": total,
        "covered": covered,
        "coverage_pct": round(100 * covered / total, 1),
        "blind_total": len(blind),
        "blind_covered": len(blind_covered),
        "hero_blind_covered": blind_covered,     # ❌ 기법 중 우리가 공격 = 히어로셋 후보
    }


def gaps() -> List[Tuple[str, str, str]]:
    """미커버 기법 (전술, ID, 이름) — 보강 후보."""
    return [(tac, tid, name) for tac, tid, name, _ in UAV_MATRIX if tid not in RED_COVER]


def hero_set() -> List[Tuple[str, str, str]]:
    """히어로셋: blue 탐지불가(❌) 기법 중 우리가 실제 공격하는 것 = 은밀 공격 실증."""
    return [(tac, tid, name) for tac, tid, name, det in UAV_MATRIX
            if not det and tid in RED_COVER]


def verified_summary() -> dict:
    """커버 기법의 근거 강도: 실 아티팩트/액션 호출가능 vs 시나리오 백엔드."""
    import re
    from .artifacts import artifact_backed
    from .attack_d3fend import MAP
    map_ids = {t for s in MAP.values() for t in s.get("attack_ics", [])}
    art = artifact_backed()
    covered = [tid for _, tid, _, _ in UAV_MATRIX if tid in RED_COVER]

    def is_callable_artifact(tid: str) -> bool:
        # ARTIFACT_REGISTRY(23) OR craft 함수(S48~S64) OR core action(MAP).
        return (tid in art or tid in map_ids
                or bool(re.search(r"S(4[89]|5[0-9]|6[0-9]|7[01])", RED_COVER[tid])))

    verified = [t for t in covered if is_callable_artifact(t)]
    return {
        "covered": len(covered),
        "callable_artifact": len(verified),          # 호출→산출물 확인 가능
        "scenario_backed": len(covered) - len(verified),  # 캠페인/assess 로 실행되는 실 시나리오
        "callable_pct": round(100 * len(verified) / len(covered), 1) if covered else 0.0,
        "no_pure_label": all(is_callable_artifact(t) or re.search(r"S[0-9]", RED_COVER[t]) for t in covered),
    }


def gaps_by_scope() -> Dict[str, List[Tuple[str, str, str]]]:
    """미커버 기법을 excluded(범위 밖)/reinforce(보강 후보)/unclassified 로 분류."""
    out: Dict[str, List[Tuple[str, str, str]]] = {"excluded": [], "reinforce": [], "unclassified": []}
    for tac, tid, name in gaps():
        out.get(GAP_SCOPE.get(tid, "unclassified"), out["unclassified"]).append((tac, tid, name))
    return out


def effective_summary() -> dict:
    """3단 커버리지: 전체 / 엄격(진짜불가 3개만 제외) — 둘 다 정직한 분모."""
    s = summary()
    # 커버되지 않았고 진짜 불가능한 것만 분모에서 제외(커버된 건 절대 빼지 않음).
    excluded = sum(1 for _, tid, _, _ in UAV_MATRIX
                   if GAP_SCOPE.get(tid) == "excluded" and tid not in RED_COVER)
    in_scope = s["total_techniques"] - excluded
    return {**s, "excluded": excluded, "in_scope": in_scope,
            "total_pct": s["coverage_pct"],
            "effective_pct": round(100 * s["covered"] / in_scope, 1) if in_scope else 0.0}
