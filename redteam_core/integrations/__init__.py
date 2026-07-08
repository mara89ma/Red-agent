"""integrations — 외부 도구 연동 계층 (고도화 §O, opt-in seam).

동언님 LLM seam(REDTEAM_LLM_PROVIDER)과 동형: 도구·표적이 env 로 지정되면 실연동,
아니면 결정론 폴백. Tier-0 무의존 유지(실연동 라이브러리는 지연 임포트).

  - ai_attack : PyRIT/Garak (S32 프롬프트인젝션·S33 모델추출)
  - caldera   : MITRE Caldera REST (C1~C10 캠페인 오케스트레이션)
  - sitl      : ArduPilot SITL/mavlink-router (§K/§C 실 텔레메트리, env 표적)
"""
from . import ai_attack, caldera, sitl, threat_intel


def integration_status() -> dict:
    """각 연동의 가용성·모드(real/fallback) 요약."""
    return {
        "ai_attack": ai_attack.status(),
        "caldera": caldera.status(),
        "sitl": sitl.status(),
        "threat_intel": threat_intel.status(),
    }


__all__ = ["ai_attack", "caldera", "sitl", "threat_intel", "integration_status"]
