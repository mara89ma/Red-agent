"""검증 강도 감사 — 능력별 검증 계층 분류.

정직 원칙: '실행됐다'와 '모델이 그렇다고 판정했다'를 절대 섞지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

TIERS = {
    "real_exec": "실행검증 — loopback 실 파일/소켓/HTTP 도달 확인",
    "grounded_model": "모델-근거있음 — 실 임계값·외부표준·실코드 introspection 근거",
    "self_model": "모델-자기충족 — 전제를 코드에 박아 assert(실측 아님)",
}


@dataclass
class AuditItem:
    capability: str
    tier: str
    count: int
    rationale: str


_AUDIT: List[AuditItem] = [
    # ── real_exec: 실제 표적 도달을 바이트로 확인 ──
    AuditItem("execute §U (MAVLink·HTTP·kubectl·exfil)", "real_exec", 25,
              "build_mavlink_* 실 프레임 + udp/http_deliver, loopback 수신 검증"),
    AuditItem("groundseg (GCS·ROS·데이터링크·클라우드)", "real_exec", 14,
              "execute_real 실 파일 쓰기·소켓·HTTP·ROS XML-RPC, loopback 실증"),
    AuditItem("information (SOCReport·OSCAL·PR)", "real_exec", 3,
              "execute_real 실 위조 아티팩트 디스크 생성, loopback 검증"),
    AuditItem("transport·persistence", "real_exec", 0,
              "실 소켓 전송·FileImplant 실 파일(§K/§L)"),
    # ── grounded_model: 근거 있는 모델 ──
    AuditItem("assessment 탐지룰(DETECTION_RULES)", "grounded_model", 0,
              "실 S1/S6/S18 임계값(z=3.0·fail>=5·unsigned)에서 시드"),
    AuditItem("benchmark KPI 목표(targets)", "grounded_model", 0,
              "ATT&CK Eval·M-Trends·CrowdStrike·JP 3-60 정박(출처 명시)"),
    AuditItem("emso J/S 물리", "grounded_model", 0,
              "번스루·포획마진 물리식(blue counter-uas와 대칭)"),
    AuditItem("mosaic judge 독립성", "grounded_model", 0,
              "실제 ensemble.py 를 inspect 로 introspection(실코드 검증)"),
    AuditItem("mapping ATT&CK 커버리지", "grounded_model", 0,
              "공개 ATT&CK-ICS/ATLAS 택소노미 매핑"),
    # ── self_model: 자기충족(정직 표시) ──
    AuditItem("dronesploit WiFi(S39~42)", "self_model", 4,
              "802.11 프레임 요지·모델, 실 주입 미구현(파라미터 손설정)"),
    AuditItem("advanced RC/DShot(S43~47)", "self_model", 5,
              "RC/ESC 아티팩트 문자열·모델, 실 SDR 미구현"),
    AuditItem("simtest 센서(S56~59)", "self_model", 4,
              "EKF 게이트 모델, 게이트값 손설정(실 HIL 미검증)"),
    AuditItem("jadc2 융합", "self_model", 0,
              "상관 임계 2.5 손설정, 실 상관기 미연동"),
    AuditItem("ooda Orient/race", "self_model", 0,
              "불확실성·속도 파라미터 예시값"),
    AuditItem("mission_command", "self_model", 0,
              "의도→목표 매핑 하드코딩(실 자율계획·LLM 아님)"),
]


def verification_audit() -> dict:
    by_tier = {t: {"items": [], "scenario_count": 0} for t in TIERS}
    for it in _AUDIT:
        by_tier[it.tier]["items"].append(it)
        by_tier[it.tier]["scenario_count"] += it.count
    real = by_tier["real_exec"]["scenario_count"]
    total_scn = sum(b["scenario_count"] for b in by_tier.values())
    return {
        "tiers": by_tier,
        "real_exec_scenarios": real,
        "self_model_scenarios": by_tier["self_model"]["scenario_count"],
        "honesty_note": (f"실행검증 {real}개 시나리오만 실제 표적 도달 확인. "
                         f"나머지는 모델(근거있음/자기충족) — '공격했다' 아니라 '판정했다'."),
    }


def format_audit(a: dict) -> str:
    out = ["검증 강도 감사 (정직성 계층)", "=" * 52]
    for tier, desc in TIERS.items():
        b = a["tiers"][tier]
        out.append(f"\n[{tier}] {desc}  (시나리오 {b['scenario_count']})")
        for it in b["items"]:
            c = f" ×{it.count}" if it.count else ""
            out.append(f"  • {it.capability}{c} — {it.rationale}")
    out.append(f"\n※ {a['honesty_note']}")
    return "\n".join(out)
