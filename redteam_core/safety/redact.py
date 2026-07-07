"""시크릿 유출 콘텐츠 redaction (E) — 캡처 사실은 남기되 원문은 외부 표면에 남기지 않음.

T3MP3ST `redactCredential` 이식(공격판): 공격이 온보드 LLM 시크릿을 획득했다는 신호
(`secret_captured`)는 보존하되, **평문 시크릿이 audit_log·report 등 외부 표면에 흘러들지
않게** SHA-256 fingerprint로 치환한다. 오라클 검증은 world 상태(`secret_leaked()`)로 하고
ACK 값에 의존하지 않으므로, redaction은 판정·안전 경로를 바꾸지 않는다.

디코이(가드레일 거부)는 `forged=True`로 구분 → `secret_captured`는 실제 캡처(¬forged)만 True.
"""

from __future__ import annotations

import hashlib


def secret_fingerprint(value: str) -> str:
    """시크릿을 되돌릴 수 없는 캡처 마커로 — 동일성 대조는 되나 원문 노출 안 함."""
    return "⟦secret_captured:" + hashlib.sha256(value.encode()).hexdigest()[:12] + "⟧"


def redact_ack(ack: dict) -> dict:
    """표적 보고 ACK에서 유출 콘텐츠를 fingerprint로 치환(원문 미기록).

    `leaked_content`가 있으면 치환하고 `secret_captured`(실제 캡처=¬forged)를 남긴다.
    `reported_label`이 유출 콘텐츠를 그대로 미러링하는 exfil 케이스에서만 함께 치환한다
    (회피의 reported_label='clear' 같은 비민감 값은 보존)."""
    out = dict(ack)
    leaked = out.get("leaked_content")
    if isinstance(leaked, str) and leaked:
        fp = secret_fingerprint(leaked)
        out["leaked_content"] = fp
        out.setdefault("secret_captured", not out.get("forged", False))
        if out.get("reported_label") == leaked:
            out["reported_label"] = fp
    return out
