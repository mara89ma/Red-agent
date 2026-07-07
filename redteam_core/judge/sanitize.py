"""증거 중립화 (C) — 간접 프롬프트 인젝션(ATLAS AML.T0051) 방어.

`LLMJudge`는 표적 보고값(ACK·STATUSTEXT 등 **적대적일 수 있는 데이터**)을 프롬프트에
넣는다. 악성/피탈 표적이 텔레메트리 문자열에 "이전 지시 무시…" 류 주입을 심으면
조언 판정을 오염시킬 수 있다(우리 코드 안의 자기 위협면).

원칙: **비신뢰 증거는 지시가 아니라 데이터다.** 이 모듈은 문자열을 순회하며
    • 역할 마커(system:/assistant:/user:)·지시 오버라이드 문구·탈옥 문구를 중립화,
    • 코드펜스/구분자 브레이크아웃을 제거,
    • 제어문자 제거·길이/깊이/개수 클램프,
하고 **적중(hit) 목록**을 함께 반환한다. 적중은 단순 스크럽으로 끝내지 않고
'표적이 주입을 시도했다'는 **관측 신호**로 리포트에 표면화한다(루프 닫기).

숫자/불리언/열거형(정상 텔레메트리)은 변경 없이 통과 — 오탐을 피한다. 표준 라이브러리만.
"""

from __future__ import annotations

import re
import unicodedata

# 프롬프트에서 비신뢰 블록을 격리하는 구조적 구분자(고정 → 결정론). 증거가 이 토큰을
# 자체 포함하면 브레이크아웃이므로 제거한다.
UNTRUSTED_OPEN = "<<UNTRUSTED_TARGET_DATA>>"
UNTRUSTED_CLOSE = "<<END_UNTRUSTED_TARGET_DATA>>"

_NEUTRAL = "⟦neutralized⟧"

# (이름, 정규식) — 대소문자 무시. 정상 텔레메트리/우리 신호엔 없는 인젝션 특유 패턴만.
_PATTERNS = [
    ("role_marker", re.compile(r"(?im)^\s*(system|assistant|user|tool|developer)\s*:")),
    ("inline_role", re.compile(r"(?i)\b(system|assistant|developer)\s*:\s*(?=\S)")),
    ("override", re.compile(
        r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}?"
        r"\b(previous|prior|above|earlier|all|any|the)\b"
        r"[^.\n]{0,40}?\b(instruction|instructions|prompt|prompts|context|rule|rules)\b")),
    ("new_instructions", re.compile(r"(?i)\bnew\s+(instruction|instructions|rule|rules)\b\s*:?")),
    ("jailbreak", re.compile(
        r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on|"
        r"developer\s+mode|do\s+anything\s+now|dan\s+mode)\b")),
    ("prompt_leak", re.compile(
        r"(?i)\b(reveal|print|repeat|show|expose)\b[^.\n]{0,30}?\b(system\s+)?(prompt|instructions)\b")),
    ("verdict_steer", re.compile(r"(?i)\b(verdict|confidence)\b\s*[:=]\s*\S")),
    ("code_fence", re.compile(r"(```+|~~~+)")),
]

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")   # \t\n\r 제외

_MAX_STR = 240
_MAX_ITEMS = 64
_MAX_DEPTH = 5


def _excerpt(s: str, n: int = 60) -> str:
    s = s.strip().replace("\n", "⏎")
    return s if len(s) <= n else s[:n] + "…"


def neutralize_str(value: str) -> tuple[str, list]:
    """문자열 하나를 중립화. (정리된 문자열, 적중 목록)."""
    hits: list = []
    original = value

    # ★ 패턴 매칭 前에 NFKC 정규화 — 전각/호환 호모글리프(예: 'ＳＹＳＴＥＭ:')가 매칭을
    #    우회한 뒤 프롬프트에서 ASCII로 접히는 것을 차단(정규화가 매칭 앞에 서야 함).
    value = unicodedata.normalize("NFKC", value)

    if _CONTROL_RE.search(value):
        hits.append({"kind": "control_char", "excerpt": _excerpt(value)})
        value = _CONTROL_RE.sub("", value)

    # 구조적 구분자 브레이크아웃 제거
    for tok in (UNTRUSTED_OPEN, UNTRUSTED_CLOSE, "<<END", "<<UNTRUSTED"):
        if tok in value:
            hits.append({"kind": "delimiter_breakout", "excerpt": _excerpt(value)})
            value = value.replace(tok, _NEUTRAL)

    for name, rx in _PATTERNS:
        if rx.search(value):
            hits.append({"kind": name, "excerpt": _excerpt(rx.search(value).group(0))})
            value = rx.sub(_NEUTRAL, value)

    # 길이 클램프(정규화는 위에서 매칭 前에 이미 수행)
    if len(value) > _MAX_STR:
        hits.append({"kind": "oversize", "excerpt": _excerpt(original)})
        value = value[:_MAX_STR] + _NEUTRAL

    return value, hits


def neutralize(value, _depth: int = 0) -> tuple:
    """JSON 유사 구조를 재귀 중립화. 숫자/불리언/None은 그대로. (정리값, 적중목록)."""
    if _depth > _MAX_DEPTH:
        return _NEUTRAL, [{"kind": "max_depth", "excerpt": ""}]

    if isinstance(value, str):
        return neutralize_str(value)

    if isinstance(value, dict):
        out, hits = {}, []
        for i, (k, val) in enumerate(value.items()):
            if i >= _MAX_ITEMS:
                hits.append({"kind": "too_many_keys", "excerpt": str(len(value))})
                break
            ck, kh = neutralize_str(str(k))
            cv, vh = neutralize(val, _depth + 1)
            out[ck] = cv
            hits.extend(kh + vh)
        return out, hits

    if isinstance(value, (list, tuple)):
        out, hits = [], []
        for i, val in enumerate(value):
            if i >= _MAX_ITEMS:
                hits.append({"kind": "too_many_items", "excerpt": str(len(value))})
                break
            cv, vh = neutralize(val, _depth + 1)
            out.append(cv)
            hits.extend(vh)
        return out, hits

    # int/float/bool/None → 신뢰(구조적으로 인젝션 불가)
    return value, []


def sanitize_evidence(untrusted) -> tuple:
    """비신뢰 증거 블록 전체를 중립화. (정리된 구조, 적중목록)."""
    if not untrusted:
        return untrusted, []
    return neutralize(untrusted)
