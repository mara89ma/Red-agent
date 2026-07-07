"""시크릿 유출 redaction 테스트 (E)."""

import copy
import json

from redteam_core.engagement.gate import _DEFAULT_PROFILE, Gate
from redteam_core.graph.build import build_graph
from redteam_core.safety.redact import redact_ack, secret_fingerprint
from redteam_core.session import build_initial_state
from redteam_core.tools.ml_target import DEFAULT_LLM_SECRET
from redteam_core.tools.range_factory import make_range


def _approver(ctx):
    return "denied" if ctx.get("physical_irreversible") else "approved"


class TestRedactUnit:
    def test_real_leak_redacted_and_flagged(self):
        ack = {"command_ack": "ACCEPTED", "action": "ml_extract_secret",
               "forged": False, "leaked_content": "MISSION_KEY_7f3a91",
               "reported_label": "MISSION_KEY_7f3a91"}
        out = redact_ack(ack)
        assert "MISSION_KEY_7f3a91" not in json.dumps(out)      # 원문 미노출
        assert out["leaked_content"] == secret_fingerprint("MISSION_KEY_7f3a91")
        assert out["reported_label"] == out["leaked_content"]   # 미러링 필드도 치환
        assert out["secret_captured"] is True                   # 실제 캡처 신호 보존

    def test_decoy_redacted_but_not_flagged_captured(self):
        ack = {"command_ack": "ACCEPTED", "forged": True,
               "leaked_content": "<REDACTED_BY_GUARDRAIL>"}
        out = redact_ack(ack)
        assert out["secret_captured"] is False                  # 디코이는 캡처 아님

    def test_non_leak_ack_untouched(self):
        ack = {"command_ack": "ACCEPTED", "action": "spoof_telemetry", "forged": False}
        assert redact_ack(ack) == ack                           # 유출 필드 없으면 무변경

    def test_evade_reported_label_preserved(self):
        # 회피의 reported_label='clear'는 비민감 → 보존(leaked_content 없음).
        ack = {"command_ack": "ACCEPTED", "action": "ml_evade_perception",
               "forged": False, "reported_label": "clear"}
        assert redact_ack(ack)["reported_label"] == "clear"


class TestRedactEndToEnd:
    def test_secret_never_in_audit_or_report(self):
        prof = copy.deepcopy(_DEFAULT_PROFILE)
        prof.setdefault("engagement", {})["abstract_action"] = "M2_copilot_exfil"
        gate = Gate(scope=prof["authorization"], budget=dict(prof["ops"]["budget"]))
        final = build_graph().invoke(
            build_initial_state(prof, gate, make_range(prof), _approver))
        blob = (json.dumps(final["audit_log"], ensure_ascii=False)
                + json.dumps(final["report"], ensure_ascii=False))
        assert DEFAULT_LLM_SECRET not in blob                   # 평문 시크릿 미유출
        assert "secret_captured" in blob                        # 캡처 사실은 기록
        # 유출은 여전히 오라클로 검증됨(redaction이 판정을 안 바꿈)
        node = next(n for n in final["ptg"].values() if n.action == "ml_extract_secret")
        assert node.status == "success"
