"""레드팀 KPI 목표 근거화 — 임의 임계 대신 외부 벤치마크·교리에 정박.

각 목표에 출처(source)와 근거(rationale)를 붙여 '왜 그 목표인가'를 설명 가능하게.
우리 지표(step/ratio)는 외부 지표(일/분)와 단위가 달라 '프록시'로 매핑함을 명시.
"""
from __future__ import annotations

# kpi_key → {value, higher_better, source, rationale}
TARGETS = {
    "attack_success_rate": {
        "value": 0.80, "higher_better": True,
        "source": "MITRE ATT&CK Evaluations (technique execution)",
        "rationale": "성숙 위협행위자 에뮬레이션의 기법 실행 성공 기준선(≥80%)."},
    "mission_degradation": {
        "value": 0.70, "higher_better": True,
        "source": "JP 3-60 MOE (Measure of Effectiveness)",
        "rationale": "임무효과 달성도 — MOE 유의미 저하 임계(교리적)."},
    "mea_reliability": {
        "value": 0.85, "higher_better": True,
        "source": "JP 3-60 MEA (Munitions Effectiveness Assessment)",
        "rationale": "효과 재현 신뢰도 — 재타격 판단 신뢰 기준."},
    "stealth_rate": {
        "value": 0.50, "higher_better": True,
        "source": "MITRE ATT&CK Eval — analytic(탐지) 미커버율 역수",
        "rationale": "ATT&CK Eval에서 분석룰 미탐지 비율이 통상 40~60% — 은밀 관통 기대선."},
    "blind_spot_ratio": {
        "value": 0.30, "higher_better": True,  # red 관점: 사각=기회
        "source": "MITRE ATT&CK Eval 분석룰 커버리지 갭",
        "rationale": "방어 분석룰 미배포 비율 — 30%↑면 red에 유의미 공격면(=blue 개선 필요)."},
    "d3fend_blind_ratio": {
        "value": 0.30, "higher_better": True,
        "source": "MITRE D3FEND 대응기법 매핑",
        "rationale": "방어대응 미매핑 비율 — 공격기법 대비 방어수단 공백."},
    "mttd_steps": {
        "value": 2.0, "higher_better": True,  # red: 늦게 탐지될수록 유리
        "source": "CrowdStrike breakout time(평균 ~62분) 프록시",
        "rationale": "킬체인 breakout(측면이동/효과) 이전 탐지 여부의 step 프록시 — 초기 1/3 내 탐지가 blue 목표."},
    "undetected_rate": {
        "value": 0.25, "higher_better": True,
        "source": "Mandiant M-Trends 체류시간(median dwell) 프록시",
        "rationale": "끝까지 미탐지 관통 비율 — dwell=∞ 캠페인, 낮을수록 blue 우수."},
    "reattack_attempts": {
        "value": 2.5, "higher_better": False,
        "source": "OODA 루프 효율(Persistent Engagement)",
        "rationale": "목표당 평균 시도수 — 낮을수록 효율적 재타격."},
    "mitre_techniques": {
        "value": 20, "higher_better": True,
        "source": "MITRE ATT&CK for ICS(∼80 기법) 부분 커버",
        "rationale": "UAV 관련 ICS/ATLAS 기법 커버 — 폭 기준선."},
    "roe_blocked": {
        "value": 1, "higher_better": True,
        "source": "SROE·DoDD 3000.09(비가역 효과 인간판단)",
        "rationale": "고위험/비가역 액션 차단 발생 — 권한 게이트 작동 증거."},
    "opsec_exposure": {
        "value": 0.35, "higher_better": False,
        "source": "OPSEC(JP 3-13.3) 노출 최소화",
        "rationale": "탐지 시그니처 노출 비율 — 낮을수록 은밀."},
    "bda_high_conf": {
        "value": 0.40, "higher_better": True,
        "source": "JP 3-60 BDA 신뢰수준(High confidence)",
        "rationale": "고신뢰 BDA 비율 — 재타격 결심 근거 품질."},
}


def target(key: str) -> dict:
    return TARGETS[key]
