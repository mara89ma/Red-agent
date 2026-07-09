"""리포팅/증거체인 실 실행 — 거짓 정보산출물을 실제 파일로 생성.

execute_real: env INFO_TARGET_DIR 지정 시 실제 위조 SOCReport/OSCAL/PR 을 디스크에
쓴다(무결성 서명 없으면 통과=성공). 미설정=fail-closed. loopback 검증.
"""
from __future__ import annotations

import json
import os
from .reporting import REPORT_TARGETS, _forge


def execute_real(scenario_id: str, integrity_signed: bool = False) -> dict:
    m = REPORT_TARGETS[scenario_id]
    forged = _forge(m["artifact"])
    d = os.environ.get("INFO_TARGET_DIR", "")
    if not d:
        return {"sent": False, "reason": "INFO_TARGET_DIR 미설정", "bytes": len(forged)}
    if integrity_signed:            # 무결성 서명이 있으면 변조 거부(쓰지 않음)
        return {"sent": False, "reason": "무결성 서명 존재 → 변조 차단", "artifact": m["artifact"]}
    os.makedirs(d, exist_ok=True)
    fn = {"soc_report": f"{scenario_id}_soc_report.json",
          "oscal_evidence": f"{scenario_id}_oscal_evidence.json",
          "rule_update_pr": f"{scenario_id}_rule_update_pr.txt"}[m["artifact"]]
    path = os.path.join(d, fn)
    data = forged.encode()
    with open(path, "wb") as f:
        f.write(data)
    return {"sent": True, "path": path, "bytes": len(data), "artifact": m["artifact"]}
