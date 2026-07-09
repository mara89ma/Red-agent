"""UAV 특화 APT 에뮬레이션 — 방산/항공우주/SATCOM 표적 위협행위자·사건 (§Q 확장).

기존 apt_emulation(범용 8종)을 UAV 도메인에 특화 보강. 실 위협 인텔·사건에 근거:
- Turla(G0010, FSB): 위성 인터넷 링크 C2 하이재킹 (Kaspersky/Securelist 문서)
- Andariel(G0138, DPRK): 방산·항공우주 사이버 espionage
- APT34/OilRig(G0049, Iran)·이란권: 드론/미사일 프로그램용 항공우주 기술 탈취(역설계)
- Gamaredon(G0047, FSB): 우크라이나 군 드론전
- RQ-170(Iran 2011): GPS 스푸핑으로 미 정찰드론 나포 — UAV GNSS 하이재킹 원형
- Counter-UAS RF/다중센서/군집 클러스터: counter-UAS 교리·EKF 기만

각 프로파일 = 기존 S-시나리오를 실 위협행위자 킬체인으로 엮음(임의 창작 아님).
결정론·무의존.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

# name → (분류, 근거, S-시나리오 체인)
UAV_APT_EMULATION: Dict[str, dict] = {
    # ── A. 실 위협행위자 (UAV/방산/SATCOM 표적, 문서화) ──
    "Turla (G0010, 위성 C2)": {
        "origin": "Russia FSB", "basis": "위성 인터넷 링크 C2 하이재킹(Securelist)",
        "chain": ["S3", "S60", "S24", "S18", "S17"]},    # SATCOM MITM→위성C2하이재킹→C2탈취→무서명→SAR유출
    "Andariel (G0138, 방산 espionage)": {
        "origin": "DPRK", "basis": "방산·항공우주 표적 espionage",
        "chain": ["S34", "S6", "S4", "S21", "S17"]},     # 정찰→GCS→펌웨어공급망→정비임플란트→유출
    "APT34/OilRig (G0049, 항공)": {
        "origin": "Iran", "basis": "항공·에너지, 드론 프로그램용 기술 탈취",
        "chain": ["S34", "S6", "S12", "S15", "S11"]},    # 정찰→GCS→자기승인→야간C4I→무장
    "Gamaredon (G0047, 드론전)": {
        "origin": "Russia FSB", "basis": "우크라이나 군 드론전(EW)",
        "chain": ["S30", "S31", "S16", "S20"]},          # GNSS재밍→C2재밍→AOI이탈→Failsafe억제
    # ── B. UAV 사건·counter-UAS 교리 클러스터 ──
    "RQ-170 GNSS Hijack (Iran 2011)": {
        "origin": "Incident", "basis": "GPS 스푸핑으로 미 정찰드론 나포",
        "chain": ["S34", "S30", "S61", "S16", "S20"]},   # 정찰→재밍→GNSS나포(S61)→AOI이탈→강제착륙
    "Counter-UAS RF Takeover": {
        "origin": "Counter-UAS", "basis": "우크라이나전 RC 링크 탈취",
        "chain": ["S41", "S43", "S44", "S46"]},          # WiFi재밍→RC바인딩탈취→override→모터
    "Multi-Sensor Deception (EKF Defeat)": {
        "origin": "Doctrine", "basis": "다중센서 스푸핑으로 EKF 무력화",
        "chain": ["S56", "S57", "S58", "S59", "S62"]},   # IMU+기압+지자기+에어스피드→협조 EKF 무력화(S62)
    "Swarm C2 Compromise": {
        "origin": "Doctrine", "basis": "군집 장악·대응 무력화",
        "chain": ["S6", "S40", "S8", "S32"]},            # GCS→EvilTwin→군집포화→LLM인젝션
    "Insider Maintenance Implant": {
        "origin": "Insider", "basis": "내부자·정비 공급망 침투",
        "chain": ["S21", "S4", "S13", "S11"]},           # 정비임플란트→펌웨어→CT하향→무장
}


@dataclass
class UavAptResult:
    name: str
    origin: str
    basis: str
    chain: List[str]
    valid: bool          # 체인의 전 시나리오가 알려진 시나리오 집합 내


def _known_scenarios() -> set:
    from ..campaigns.chains import _SCENARIO_ACTION, _SCENARIO_STATIC
    known = set(_SCENARIO_ACTION) | set(_SCENARIO_STATIC)
    # 배포 원본 S1~S29(일부는 chains 에 없어도 정본 시나리오) 포함.
    known |= {f"S{i}" for i in range(1, 30)}
    from ..payloads.uav_novel import NOVEL_SCENARIOS      # 신규 S60~S62
    known |= set(NOVEL_SCENARIOS)
    return known


def run_uav_apt(name: str) -> UavAptResult:
    """UAV 특화 APT 체인 반환 + 전 시나리오 유효성 검증."""
    p = UAV_APT_EMULATION[name]
    known = _known_scenarios()
    valid = all(s in known for s in p["chain"])
    return UavAptResult(name, p["origin"], p["basis"], list(p["chain"]), valid)


def uav_apt_names() -> List[str]:
    return list(UAV_APT_EMULATION)
