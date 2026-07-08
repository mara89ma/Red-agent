"""MITRE ATT&CK Navigator 레이어 생성 (§N 확장).

동언님 mapping.attack_d3fend.MAP + 탐지 분류(_classify)로 Navigator layer JSON 을
만든다. 색으로 탐지상태 표기: 사각지대=적, 회피가능=주황, 탐지됨=녹.
attack-navigator 에 import 하면 커버리지 히트맵으로 시각화된다.
"""
from __future__ import annotations

from typing import Dict, List

from .metrics import _classify

_COLOR = {"blind": "#e74c3c", "evadable": "#f39c12",
          "detected_only": "#27ae60", "robust": "#27ae60"}
_LABEL = {"blind": "사각지대(미탐지)", "evadable": "회피가능",
          "detected_only": "탐지됨", "robust": "견고(항상탐지)"}


def _nav_classify(action: str) -> str:
    """탐지상태를 **배포룰 실태** 기준으로 보정(정직성).

    _classify 는 에이전트 배선된 5개 룰만 알아 미배선 물리기법을 '사각'으로
    보지만, blue 는 대부분 배포룰이 있다. 진짜 사각은 jam(재밍)·ML(AI) 계열뿐.
    """
    from ..tools.ml_target import ML_ACTIONS
    genuine_blind = {"jam"} | set(ML_ACTIONS)
    cls = _classify(action)
    if cls == "blind":
        return "blind" if action in genuine_blind else "detected_only"
    return cls


def _technique_status() -> Dict[str, str]:
    """기법ID → 대표 탐지상태(탐지>회피>사각 우선)."""
    from ..mapping.attack_d3fend import MAP
    order = {"detected_only": 3, "robust": 3, "evadable": 2, "blind": 1}
    best: Dict[str, str] = {}
    for action, spec in MAP.items():
        cls = _nav_classify(action)
        for tid in spec.get("attack_ics", []):
            if tid not in best or order[cls] > order[best[tid]]:
                best[tid] = cls
    return best


def build_navigator_layer(domain: str = "ics-attack") -> dict:
    """domain: ics-attack(T0*) | enterprise-attack(T1*) | atlas(AML*)."""
    prefix = {"ics-attack": "T0", "enterprise-attack": "T1", "atlas": "AML"}[domain]
    techs: List[dict] = []
    for tid, cls in _technique_status().items():
        if not tid.startswith(prefix):
            continue
        techs.append({
            "techniqueID": tid, "score": 1, "color": _COLOR[cls],
            "comment": _LABEL[cls], "enabled": True,
        })
    return {
        "name": f"fried-pollack-ai red coverage ({domain})",
        "versions": {"layer": "4.5", "navigator": "4.9.1"},
        "domain": domain,
        "description": "레드 에이전트 기법 커버리지 + blue 탐지상태(적=사각/주황=회피/녹=탐지)",
        "techniques": sorted(techs, key=lambda t: t["techniqueID"]),
        "gradient": {"colors": ["#e74c3c", "#27ae60"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": v, "color": _COLOR[k]} for k, v in
                        {"blind": _LABEL["blind"], "evadable": _LABEL["evadable"],
                         "detected_only": _LABEL["detected_only"]}.items()],
    }
