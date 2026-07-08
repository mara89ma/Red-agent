"""캠페인 체인 상세 러너 — 단계별 페이로드·에스컬레이션·탐지 산출.

킬체인 상세(보고서/Notion)를 손으로 쓰지 않고 코드로 생성한다. 각 단계 =
시나리오 메타(페이로드·기법·에스컬레이션·계층) + run_chain 탐지결과 결합.
결정론·무의존.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .chains import CHAINS, run_chain

# 시나리오 메타: (이름, 실제 페이로드 예, 기법, 에스컬레이션, 계층)
# 에스컬레이션: 🟢자동 🟡HITL(COMPONENT) 🟠JFC(비가역) 🔴NATIONAL+JCEOI(EW) ⛔ConOps밖
SCENARIO_META = {
    "S1":  ("GNSS 스푸핑", "MAVLink GPS_INPUT 프레임(71B)", "T0842/EW", "🔴", "OT"),
    "S4":  ("펌웨어 변조", "POST /preflight {hash:deadbeef, sbom:false}", "T1195", "🟡", "OT"),
    "S11": ("무장", "POST /arm {action:ARM}", "ICS 무장", "⛔/🟠", "OT"),
    "S12": ("임무 자기승인", "POST /plan {planner==approver}", "IDOR/T1078", "🟡", "OT"),
    "S16": ("AOI 이탈", "telemetry: 좌표 ∉ AOI 박스", "T0831", "🟡", "OT"),
    "S17": ("SAR 좌표 유출", "SAR 타깃 exfil 레코드", "T1041", "🟡+exfil", "OT"),
    "S48": ("인증우회/IDOR", "GET /weapon/operator-02", "IDOR/T1078", "🟡", "IT"),
    "S49": ("웹셸 업로드", "imagery.php: <?php system($_GET['c']); ?>", "T1505.003", "🟡", "IT"),
    "S50": ("SUID/GTFOBins", "find . -exec /bin/sh -p \\; -quit", "T1548.001", "🟠", "IT"),
    "S51": ("컨테이너 escape", "podspec: hostPath /var/run/docker.sock", "T1611", "🟠", "IT"),
    "S52": ("cron 하이재킹", "/etc/cron.d/rogue: * * * * * root /opt/rogue", "T1053.003", "🟡", "IT"),
    "S53": ("아카이브 Zip Slip", "zip 엔트리 ../../../opt/uav/startup.d/rogue.sh", "CWE-22/T1195", "🟡", "IT"),
}

_CHAIN_NARRATIVE = {
    "C14": "악성 아카이브(Zip Slip)로 펌웨어 번들에 임플란트 드롭 → 펌웨어 변조 → 변조 기체 GNSS 스푸핑. 전달은 파일추출 계층이라 UAV SOC 사각.",
    "C15": "웹셸로 스텁 침해 → 컨테이너 escape 로 호스트 장악 → 그 권한으로 임무 자기승인 → 무장. IT 발판은 사각이나 OT 임무층에서 잡힘.",
    "C16": "웹셸→SUID 권한상승→컨테이너 escape→cron 지속. 전 단계가 IT 계층이라 UAV Sentinel 완전 사각(최악 공백).",
    "C17": "악성 아카이브 전달 → 웹셸 → SAR 좌표 유출. 전달·웹셸은 사각, 유출 룰(S17)에서 탐지.",
    "C18": "인증우회(IDOR)로 무장 엔드포인트 직접 접근 → 무장 시도. 우회는 사각이나 무장 범주형(2인통제) 견고차단.",
}


@dataclass
class StageDetail:
    sid: str
    name: str
    payload: str
    technique: str
    escalation: str
    layer: str
    detected: Optional[bool]      # True=🔴탐지 / None=⚪사각


@dataclass
class ChainDetail:
    chain_id: str
    verdict: str
    narrative: str
    stages: List[StageDetail]
    first_detected: Optional[str]


def chain_detail(chain_id: str) -> ChainDetail:
    """체인의 단계별 페이로드·에스컬레이션·탐지를 코드로 산출."""
    r = run_chain(chain_id)
    det = {sid: d for sid, _, d in r.stages}
    stages = []
    for sid in CHAINS[chain_id]:
        name, payload, tech, esc, layer = SCENARIO_META.get(
            sid, (sid, "-", "-", "-", "-"))
        stages.append(StageDetail(sid, name, payload, tech, esc, layer, det.get(sid)))
    first = r.detected_at[0] if r.detected_at else None
    return ChainDetail(chain_id, r.verdict, _CHAIN_NARRATIVE.get(chain_id, ""), stages, first)
