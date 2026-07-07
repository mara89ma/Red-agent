"""결과 프로브 (B8) — 환경검증 결과만 durable 학습으로 fan-out.

pollack `core/outcome.py`/`outcome_probe_agent.py`의 공격판. PTG 노드의 최종 상태
(out-of-band validator가 확정)를 결정론 매트릭스로 verdict+effect에 매핑하고,
경험 게이트(B6)와 타깃 프로파일 게이트(B7)로 각각 흘려보낸다. '게이트 도달(blocked)'
은 물리 효과가 아니므로 INCONCLUSIVE로 학습에서 제외한다.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..tools.ml_target import STAGED_ONLY_ACTIONS
from .experience import (CONFIRMED_FAIL, CONFIRMED_SUCCESS, INCONCLUSIVE,
                         ExperienceRecord)
from .fingerprint import is_empty_target, resolve_target_id

# 정찰·순수 스테이징 액션은 검증 가능한 공격 '효과'가 없다 → 학습 제외.
# validator의 effect 제외 집합("recon","ml_craft","ics_scan")과 정합시켜, recon/스테이징이
# 'proven action'으로 오학습되거나 타깃 프로파일을 오염시키지 않게 한다.
_NON_EFFECT_ACTIONS = {"recon_heartbeat", "active_scan",
                       "ml_craft_adversarial"} | STAGED_ONLY_ACTIONS


@dataclass
class Observation:
    target_id: str
    technique: str
    action: str
    status: str                 # PTG 노드 최종 상태(success|failed|blocked)


class ProbeEngine:
    """결정론 매트릭스 — 관측 → (verdict, effect)."""

    @staticmethod
    def decide(obs: Observation) -> tuple:
        if obs.status == "success":
            return CONFIRMED_SUCCESS, 1.0
        if obs.status == "failed":
            return CONFIRMED_FAIL, 0.0
        # blocked/open/in_progress = 물리 효과 미발생 → 학습 제외
        return INCONCLUSIVE, 0.0


def _defenses_from_profile(profile: dict) -> dict:
    dl = profile.get("target_profile", {}).get("datalink", {})
    return {"mavlink_signing": dl.get("mavlink_signing"),
            "arming_check": dl.get("arming_check")}


def learn_from_state(state: dict, exp_gate, tgt_gate) -> dict:
    """엔게이지먼트 종료 시 1회 — PTG 결과를 경험/타깃 프로파일로 학습(루프 닫기)."""
    profile = state["profile"]
    target_id, explicit = resolve_target_id(profile)
    if is_empty_target(target_id):
        return {"skipped": "empty_target"}

    tgt_gate.observe_defenses(target_id, _defenses_from_profile(profile))

    written = 0
    for node in state["ptg"].values():
        if node.action in _NON_EFFECT_ACTIONS:           # recon/스테이징 → 학습 제외
            continue
        verdict, effect = ProbeEngine.decide(
            Observation(target_id, node.technique, node.action, node.status))
        rec = ExperienceRecord(target_id, node.technique, node.action, verdict, effect,
                               provenance="validator")     # out-of-band 오라클 = 신뢰
        if exp_gate.write.write(rec):
            written += 1
        # 타깃 프로파일은 INCONCLUSIVE(blocked)도 kill_chain 기록엔 유용 → effect만 반영
        tgt_gate.record_attempt(target_id, node.action, node.technique, effect)

    tp = tgt_gate.get(target_id)
    return {
        "target_id": target_id,
        "explicit_id": explicit,
        "experiences_written": written,
        "prior_success_recall": [r.action for r in exp_gate.read.recall(target_id, "success")],
        "target_profile": {
            "observed_defenses": tp.observed_defenses if tp else {},
            "techniques_attempted": tp.techniques_attempted if tp else [],
            "pb_scores": tp.pb_scores if tp else {},
        },
    }


def recommend(target_id: str, exp_gate, tgt_gate) -> dict:
    """다음 엔게이지먼트용 권고 — 통한 playbook(효과 내림차순) + 건너뛸 기법(신뢰 FAIL)."""
    tp = tgt_gate.get(target_id)
    proven = []
    if tp:
        proven = sorted(((a, s["avg_effect"], s["n"]) for a, s in tp.pb_scores.items()
                         if s["avg_effect"] > 0.0),
                        key=lambda x: x[1], reverse=True)
    skip = sorted({r.action for r in exp_gate.read.recall(target_id, "failure")})
    return {
        "target_id": target_id,
        "proven_actions": [a for a, _, _ in proven],
        "proven_detail": [{"action": a, "avg_effect": round(e, 3), "n": n}
                          for a, e, n in proven],
        "skip_actions": skip,
    }
