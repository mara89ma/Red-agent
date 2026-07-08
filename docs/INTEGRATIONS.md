# 외부 연동 가이드 (§O integrations)

> 레드 에이전트의 외부 도구 연동은 **opt-in seam**이다: env 를 지정하면 실연동(real),
> 아니면 결정론 폴백(fallback)으로 Tier-0 무의존 동작을 유지한다(동언님 LLM seam과 동형).
> **정직성 표기**: SITL 은 실 전송이 구현됨. PyRIT/Garak·Caldera 는 seam 이 활성화되나
> 실 호출부(`_run_real`, `pragma: no cover`)는 본선/실환경에서 완성한다.

---

## 0. 상태 확인 (공통)

```python
from redteam_core.integrations import integration_status
integration_status()
# {'ai_attack': {'mode': 'fallback'...}, 'caldera': {...}, 'sitl': {...}}
```
또는 데모:
```bash
python benchmarks/integrations_eval.py
```
env 미지정이면 세 연동 모두 `fallback`. env 지정 시 해당 연동만 `real` 로 전환.

---

## 1. ArduPilot SITL / mavlink-router  (✅ 실 전송 구현됨)

**대상**: §K 전송·§C EMSO 를 실 텔레메트리로. `uav-sim-env` 의 SITL + mavlink-router.

**준비**
```bash
# (A) uav-sim-env 로컬(kind) 또는 AKS 기동 → mavlink-router tap 포트 확인
#     예: datalink-los 의 UDP 14550 / tap 14552
# (B) pymavlink 설치(실 MAVLink 프레임 인코딩용)
pip install pymavlink
```

**env**
```bash
export MAVLINK_ENDPOINT="10.50.0.40:14550"   # mavlink-router 표적
export C2_HOST="10.50.0.99"; export C2_PORT="8080"
export STUB_URL="http://auth-stub.ground.svc:8080"
```

**검증**
```python
from redteam_core.integrations import sitl
sitl.status()                 # mode == 'real'
sitl.inject_gps_spoof()       # {'mode':'real','endpoint':...,'bytes':N} — 실 UDP 전송
```
> ⚠️ **시험창·허가 환경에서만.** 실 표적 지정은 통제된 SITL 대상만.

---

## 2. PyRIT / Garak  (AI 공격 — seam 활성, 실 호출부 본선)

**대상**: S32 프롬프트 인젝션·S33 모델 추출을 표적 LLM(예: SOC LLM)에 실행.

**준비**
```bash
pip install pyrit          # 또는: pip install garak
```

**env**
```bash
export AI_ATTACK_PROVIDER="pyrit"          # pyrit | garak
export AI_TARGET_URL="http://soc-llm.local:8000/v1/chat/completions"
```

**검증**
```python
from redteam_core.integrations import ai_attack
ai_attack.status()                          # mode == 'real' (라이브러리+env 있을 때)
ai_attack.run_ai_attack("prompt_injection")
```
> `run_ai_attack` 의 실 호출부 `_run_real` 은 PyRIT `PromptSendingOrchestrator` /
> Garak `probe` 를 `AI_TARGET_URL` 에 실행하도록 **본선에서 완성**한다(현재는 경로만).

---

## 3. MITRE Caldera  (캠페인 오케스트레이션 — seam 활성, 실 호출부 본선)

**대상**: 캠페인 체인 C1~C10 을 Caldera operation 으로 오케스트레이션.

**준비**
```bash
# Caldera 서버 기동(별도 호스트)
git clone https://github.com/mitre/caldera --recursive && cd caldera
python server.py --insecure    # 기본 :8888, API 키는 conf/local.yml
```

**env**
```bash
export CALDERA_URL="http://caldera.local:8888"
export CALDERA_API_KEY="<conf/local.yml 의 api_key_red>"
```

**검증**
```python
from redteam_core.integrations import caldera
caldera.status()                # mode == 'real'
caldera.run_operation("C9")
```
> 실 호출부 `_run_real` 은 `POST {CALDERA_URL}/api/v2/operations` 로 adversary/ability
> 매핑을 실행하도록 **본선에서 완성**한다(현재는 경로만). 폴백은 내부 §M 실행.

---

## 4. 안전·법적 고지

- **전자전(EW, S30·S31)**: 실 RF 방사(gps-sdr-sim/GNU Radio 등)는 허가·차폐환경에서만.
  §B RoE 게이트가 JCEOI 미승인 EW 를 사전 차단한다.
- **물리 비가역**: takeoff/disarm/flight_terminate 는 HITL 인간 승인 없이는 실집행 불가(불변식).
- **표적 지정**: 모든 실 표적은 시험창·통제 환경 전용. 기본값은 loopback/폴백.

## 5. 폴백 동작 (env 미지정)

| 연동 | 폴백 |
|---|---|
| ai_attack | 결정론 사각지대 판정(assess) |
| caldera | 내부 §M 캠페인 실행(run_chain) |
| sitl | 무전송(프레임 생성만) / loopback |

전 연동은 env 없이도 결정론으로 동작하므로 CI·데모·오프라인 검증이 항상 가능하다.
