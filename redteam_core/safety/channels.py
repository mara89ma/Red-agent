"""채널 분리 + provenance 태깅 (§2.8 channels.py).

표적발 데이터(MAVLink 텔레메트리 포함)는 **데이터일 뿐 지시가 아니다**
(Mantis 2410.20911: 방어자가 공격 LLM에 프롬프트 인젝션 역공 가능).
"""

from __future__ import annotations

# 채널 종류. 툴출력/표적콘텐츠는 절대 '지시'로 승격되지 않는다.
SYSTEM_POLICY = "system_policy"
USER_INSTRUCTION = "user_instruction"
TOOL_OUTPUT = "tool_output"
TARGET_CONTENT = "target_content"

_UNTRUSTED = {TOOL_OUTPUT, TARGET_CONTENT}


def tag(channel: str, payload) -> dict:
    return {"channel": channel, "trusted": channel not in _UNTRUSTED, "payload": payload}


def is_instruction(tagged: dict) -> bool:
    """표적발/툴출력은 지시가 될 수 없다(False)."""
    return tagged.get("channel") in (SYSTEM_POLICY, USER_INSTRUCTION)
