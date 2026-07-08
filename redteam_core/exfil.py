"""데이터 유출(Exfiltration) 시나리오 메타데이터 — S35~S38.

방산에서 데이터 유출은 핵심 위협면인데 기존은 S17(SAR 좌표)에 국한. 전용 유출
시나리오를 추가한다. 전부 blue 전용 탐지룰 미배포 = 사각지대(방어 보강 지점).

핵심 서사: S38 암호키 유출 → MAVLink 서명키 탈취 → 서명 위조로 S18(무서명 탐지) 우회.
"""
from __future__ import annotations

EXFIL_SCENARIOS = {
    "S35": {"name": "대량 영상/SAR 유출", "mitre": "T1020", "objective": "data_exfiltration",
            "asset": "SAR_PAYLOAD/EOIR", "note": "UAVImagery/SAR 대량 유출"},
    "S36": {"name": "C2 채널 은닉 유출", "mitre": "T1041", "objective": "covert_exfil",
            "asset": "C2_LINK", "note": "상용포트 C2 로 은닉 유출"},
    "S37": {"name": "스테이징 후 분할 유출", "mitre": "T1074/T1030", "objective": "staged_exfil",
            "asset": "GCS", "note": "스테이징 디렉토리 집적 후 대역폭 제한 분할"},
    "S38": {"name": "암호키 유출", "mitre": "T1552/T1555", "objective": "crypto_key_exfil",
            "asset": "AUTOPILOT/GCS", "note": "MAVLink 서명키·세션토큰·TLS키 탈취 → S18 우회"},
}


def run_exfil(scenario_id: str) -> dict:
    """유출 시나리오를 에이전트로 실행(§E)."""
    from .assessment import adaptive_engage
    meta = EXFIL_SCENARIOS[scenario_id]
    r = adaptive_engage(meta["objective"])
    detected = r.trace[-1][2].detected if r.trace else None
    return {"scenario": scenario_id, "name": meta["name"], "mitre": meta["mitre"],
            "verdict": r.verdict, "winning_ttp": r.winning_ttp, "detected": detected}
