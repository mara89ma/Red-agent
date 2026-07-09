"""리포팅/증거체인 공격 — 거짓 정보산출물 생성.

세 표적: SOCReport(사건보고)·OscalEvidence(규정준수 증거)·RuleUpdate PR(룰 변경).
무결성 검증(서명/해시)이 없으면 조작이 통과 = 새 사각(정보 무결성 계층).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

# 시나리오 → 정보산출물 표적
REPORT_TARGETS = {
    "S100": {"name": "SOCReport 위조", "artifact": "soc_report",
             "goal": "탐지 결과와 무관한 거짓 사건보고 산출"},
    "S101": {"name": "OSCAL 증거 변조", "artifact": "oscal_evidence",
             "goal": "규정준수 증거체인 조작(감사 회피)"},
    "S102": {"name": "RuleUpdate PR 주입", "artifact": "rule_update_pr",
             "goal": "룰 변경 PR 본문에 백도어 완화조건 삽입"},
}


@dataclass
class InfoAttackResult:
    scenario: str
    artifact: str
    forged: str                 # 조작된 산출물(요지)
    integrity_signed: bool      # 무결성 서명 존재?
    tamper_detected: bool       # 변조 탐지됨?
    success: bool               # 거짓 산출물이 통과
    note: str


def _forge(artifact: str) -> str:
    if artifact == "soc_report":
        return json.dumps({"incident": "NONE", "severity": "Informational",
                           "note": "정상 훈련(위조)", "true_state": "attack_in_progress"})
    if artifact == "oscal_evidence":
        return json.dumps({"control": "AC-2", "result": "satisfied",
                           "evidence": "(변조: 실패를 성공으로)"})
    return "PR: relax S1 zScoreThreshold 3.0->9.9 (사실상 무력화, 정상 튜닝 위장)"


def attack_reporting_chain(scenario_id: str, integrity_signed: bool = False) -> InfoAttackResult:
    """정보산출물 조작. 무결성 서명 없으면 변조 미탐(통과=성공)."""
    m = REPORT_TARGETS[scenario_id]
    forged = _forge(m["artifact"])
    # 서명/해시 체인이 있으면 변조 탐지, 없으면 통과.
    tamper_detected = integrity_signed
    success = not tamper_detected
    note = ("무결성 서명 부재 → 거짓 정보산출물 통과(진실/기록 자체를 오염). "
            "= 탐지 정오와 무관한 새 공격 축" if success
            else "무결성 서명이 변조 탐지 → 차단")
    return InfoAttackResult(scenario_id, m["artifact"], forged, integrity_signed,
                            tamper_detected, success, note)
