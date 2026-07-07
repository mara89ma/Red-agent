# ARCHITECTURE — UAV 대상 AI 레드팀 에이전트

fried-pollack-ai는 **UAV(무인기) 대상 공격측 AI 레드팀 에이전트**다. 설계 논지는 하나로 요약된다:

> **물리 비가역 명령의 판정 권한은 모델 밖(결정론 게이트 + out-of-band 오라클)에 있어야 안전하다.**

그래서 이 에이전트는 LLM ReAct 자율 루프를 **의도적으로 피하고**, 결정론 파이프라인 + 조언
전용 LLM(오라클 veto 하) + 메모리 기반 학습으로 구성된다. 근거 논문·이식 출처는
[`REFERENCES.md`](REFERENCES.md).

**현재 규모**: Python 모듈 68 · 원자 액션 22 · 무기고 커버 **23/23=100%**(런타임검증 95.7%,
AML.T0020 스테이징) · 벤치 16 시나리오/**8 PoV 페어** · **182 tests green** · Tier-0(무의존 실행).

> **문서 자립성**: 이 문서는 **저장소만 클론해도 완결**되도록 작성됐다. 코드 주석의 외부
> 설계원문 `§`-번호(§1.0·§1.6·§2.7 등)는 **§15 크로스워크**로 이 문서 내부 절에 매핑되고,
> 탐지 계약(ATT&CK-ICS→UAV*_CL→D3FEND)은 **§11에 내장**했다. 외부 파일 의존 없음.

---

## 0. 표적 도메인 모델 — `uav-sim-env` (KUS-FS급 MUAV)

표적은 단일 드론이 아니라 **다중 프로토콜·다호스트 사이버-물리 시스템**이며, 격리 컨테이너
레인지로 모사된다. 에이전트는 이 토폴로지를 하드코딩하지 않고 `engagement_profile.yaml`의
`target_profile`/`observables`로 파라미터화한다(§2 "환경=YAML").

```
 네트워크 10.50.0.0/24 (scope_cidr — 하드 allowlist)
 ┌──────────────┐  MAVLink 5760  ┌────────────────────────┐  UDP 14550   ┌──────────────┐
 │ av-muav       │───────────────▶│ datalink-los           │─────────────▶│ gcs-qgc      │
 │ ArduPilot SITL│  10.50.0.10    │  mavlink-router+netem  │  10.50.0.30  │ QGC+noVNC    │
 │ +Gazebo, 편대 │  sysid=1       │  TcpServerPort :5790 ◀─┼── 외부접속점 │ :8080/:5900  │
 │ 2~4대         │                │  (무인증 = A4 진입점)  │  (UNAUTH)    └──────────────┘
 └──────┬────────┘                │  UDP tap_out 14552 ────┼──▶ telemetry-tap(10.50.0.40)
        │ MAVLink                 └────────────────────────┘        │ pymavlink→NDJSON
        ▼                                                            ▼  UAV*_CL (관측 로그)
 ┌────────────────────────┐                          ┌───────────────────────────────────┐
 │ datalink-satcom        │  satcom.ndjson           │ FastAPI stubs:                     │
 │ OpenSAND ST/SAT/GW(GEO)│─────────────▶ S3 표면    │ pgse / auth:8600 / mps / weapon:8400│
 │ session/seq/integrity  │  UAVSatcomLink_CL        │ ti:8500 / c4i / cyber-posture / sar│
 └────────────────────────┘                          └───────────────────────────────────┘
```

**설계를 좌우하는 도메인 통찰 4가지:**
1. **물리 가역성이 곧 위험 등급.** 비행 중 disarm = 추락(비가역). → 위험 등급·HITL·롤백의 1차 축.
2. **ACK ≠ 물리 상태 변화.** `COMMAND_ACK=ACCEPTED`는 *수신*만 의미하고 위조도 가능
   (ArduPilot 2512.01164). → Validator가 자기보고를 신뢰하지 않는 근거(§6·D2).
3. **표적이 역공 함정일 수 있다.** 스푸핑된 텔레메트리로 에이전트를 오판 유도 가능
   (Mantis 2410.20911). → 표적발 데이터(MAVLink 텔레메트리 포함) 전부 **untrusted**. 검증
   신뢰근거는 표적발이 아니라 **공격 경로 밖 ground truth**(Gazebo 물리상태·HIL 계측)여야 한다.
4. **환경이 공격에 유리하게 노출됨(레인지 특성).** `ARMING_CHECK=0` 강제·전량 비서명 MAVLink →
   force-arm·인젝션이 자명. **탐지격차 실험의 이상적 출발점**(난이도를 정보공개량으로 조절).

**시나리오 라벨**(레인지 자체 어휘 채택): **S1** GNSS 스푸핑 · **S3** SATCOM MITM/세션하이재킹/재밍
· **S4** 펌웨어/공급망 변조 · **A4** MAVLink 평문 인젝션 · **JAM** 재밍/DoS · (+) 2인통제 위반·세션도용.

### 0.1 공격면 (진입점 → 1차 공격)

| 계층 | 진입점(주소·포트) | 인증 | 1차 공격(라벨) | 원자 액션 |
|---|---|---|---|---|
| 데이터링크 | **`datalink-los:5790`** (TcpServerPort) | **무인증** | **A4** 평문 MAVLink 인젝션 | `unauthorized_command`·`force_arm`·`set_mode` |
| 데이터링크 | `av-muav:5760` (SITL) | — | recon(HEARTBEAT·PARAM) | `recon_heartbeat`·`param_read` |
| 라우팅 | mavlink-router (5790/14550/14552) | — | MITM 삽입·측면이동 | `c2_common_port` |
| GCS/컴패니언 | `gcs-qgc:8080`(noVNC)·`:5900`(VNC) | 약함 | 콘솔 하이재킹·세션도용 | (companion 분기) |
| SATCOM | `datalink-satcom` (OpenSAND) | — | **S3** MITM·세션하이재킹·재밍 | `satcom_mitm`·`jam` |
| 항법 | `SIM_GPS_*` / 차폐 SDR(L1) | — | **S1** GNSS 스푸핑/재밍 | `gnss_spoof`·`jam` |
| 지상지원 | `pgse-stub` REST(`/preflight`,`/armory/firmware`) | 약함 | **S4** 펌웨어/SBOM 변조 | (http, 스테이징) |
| 운영 | `auth:8600`·`weapon:8400`·`c4i` | 약함 | 인증우회·2인통제 위반·exfil | `disable_protection` |

> **S3 경계 명시**: OpenSAND 제어평면(빔/물리계층)=out-of-scope / 세션·무결성 태깅 평면
> (link_id·seq·session·integrity)=in-scope. S3 MITM은 태깅 평면 대상이라 egress allowlist가
> S3 공격을 막지 않는다.

---

## 1. 세 기둥

| 기둥 | 뜻 | 구현 |
|---|---|---|
| **scaffold = 능력** | 무엇을 할 수 있나 | 원자 액션 레지스트리 + playbook + 능력 평면(§5) |
| **oracle = 진위** | 정말 일어났나 | out-of-band ground truth 검증(§6, ACK≠state) |
| **gate = 안전** | 해도 되나 | 결정론 가역성 테이블 + 3중 방어 + HITL(§4) |

3줄 설계 원칙: ① Executor는 가장 좁고 강하게 통제(물리 비가역 → 통제 강도 ↑↑). ② 채팅이
아니라 Task Graph(PTG)가 메모리. ③ 모든 안전 통제는 모델 밖에 산다.

---

## 2. 설계 불변식 (D 시리즈)

| ID | 불변식 |
|---|---|
| **D2** | 검증은 자기보고(ACK)·LLM이 아니라 **out-of-band ground truth**로. LLM은 조언만(판정권 없음). |
| **D8** | fried-pollack-ai ↔ pollack-ai(SOC)는 **별개 프로젝트, 코드 결합 없음**. 유일 접점은 단방향 `UAV*_CL` 브릿지(§11). |
| 환경=YAML | IP·좌표·초기상태·임계값은 코드가 아니라 `engagement_profile.yaml`(`target_profile`/`observables`/`sim`)에서. |
| 물리 비가역 = 인간 전용 | takeoff/disarm(비행중)/flight_terminate는 자동 경로 없음 — HITL 인간 승인 + 단발 토큰만. |
| Tier-0 | 핵심 실행은 무의존(stdlib). LLM·pydantic 등은 **선택적** seam. |

---

## 3. 파이프라인 (결정론 LangGraph 상태머신)

```
START → recon → planner → synth → checker ─(ok)→ [broker→HITL?] → executor
                                     └(violation)→ reflection
        → summarizer → validator → reflection ─(continue)→ planner
                                              ├(rescan)→ recon
                                              └(stop)→ reporter → END
```

- **LLM은 이 경로에 없다.** planner=결정론 playbook 전개, 라우팅=규칙 함수
  (`route_after_checker/hitl/reflection`). LLM은 오직 §8 judge에서 조언으로만.
- **Receding-horizon**(FLARE): planner가 1스텝 커밋 → reflection이 결과 확정 후 다음 스텝.
- LangGraph 미설치 시 동일 라우팅 **stdlib 러너**로 자동 폴백(무의존 데모 보장).

노드별 책무:
| 노드 | 책무 |
|---|---|
| recon | 결정론 파싱으로 typed 사실 적재(환각 방지). 측면이동 발견 시 재진입 가능 |
| planner | 추상 액션 → 원자 PTG 노드 전개 + **학습 skip 배선**(§7.3) |
| synth | 정적 KB 스펙에 맞춰 명령 조립(`think` 근거 보존) |
| checker | sysid allowlist·구문 검증·`think` 누출 0 |
| broker | read/write 분할(최소권한) |
| HITL | write_highrisk/physical_irreversible 인간 승인 게이트 |
| executor | 격리 공격박스 1명령 적용 + **토큰 강제**(§4) + **ACK redaction**(§10) |
| validator | **out-of-band 오라클 검증**(§6) + **judge 앙상블**(§8) |
| reflection | 상태 확정·실패분류·루프탐지·라우팅 |
| reporter | 감사로그에서 finding + 탐지격차 + intel/judge/opsec/learning 집계 |

### 3.1 추상 액션 ↔ HITL 분리 (핵심 혁신)

Incalmo식 추상 고수준 액션(약한 모델도 동작)과 스텝별 물리 HITL의 모순을 **계획 단위 vs
실행 단위 분리**로 해소한다.

- **추상 액션 = 계획 단위**: Planner는 `hijack`을 1개 *추상* PTG 노드로 추론(playbook 재사용 이득).
- **전개 = 원자 노드 시퀀스**: 추상 노드를 **원자 PTG 노드의 하위 시퀀스로 즉시 전개** —
  `set_mode(GUIDED)[write_lowrisk] → force_arm[write_highrisk] → takeoff[physical_irreversible]`.
  **각 원자 노드가 독립 `risk_tier`·`reversibility` 보유**(한 노드 = 한 등급). 추상 노드 자체는
  executor에 도달하지 않는다.
- **게이트 = 원자 노드마다, 실행 직전, 라이브 상태로**: `route_to_hitl`은 계획 시점 캐시값이
  아니라 그 tick에 독립 오라클이 읽은 라이브 `armed/in_flight/alt`로 `classify()`를 재실행
  (§4.2 TOCTOU 차단). **C2 ability와 원자 노드가 1:1 대응.**

---

## 4. 안전 아키텍처

### 4.1 결정론 가역성 테이블 (`safety/reversibility.py`)
`classify(live_state, action) → (risk_tier, gate)`. **판정권은 LLM이 아니라 이 테이블**.
등급: `read < write_lowrisk < write_highrisk < physical_irreversible`. 미지 액션은
**fail-closed**(최고 등급). ML/ICS 디지털 액션은 물리 비가역 아님(§5). **입력은 항상 라이브
상태**(계획 시점 캐시 금지 — TOCTOU 차단).

전체 결정 규칙(§1.7 원문):

| `physical_state` × action | 가역성 | 게이트 | 근거 |
|---|---|---|---|
| on-ground · `set_mode`(DO_SET_MODE 176) | 가역 | low (자동) | 모드만 변경, 즉시 되돌림 |
| on-ground · `force_arm`(ARM 400,p1=1) | 준가역 | **HITL** | disarm 가능하나 추진계 활성 |
| **in-flight · `disarm`(400,p1=0)** | **비가역(추락)** | **인간 전용 hard** | 모터 정지=낙하 |
| any · `flight_terminate`(DO_FLIGHTTERMINATION 185) | 비가역 | **인간 전용 hard** | 비행 종료 |
| any · `param_set_safety` `FS_*`/`GEOFENCE`/`ARMING_CHECK` | 조건부 | **HITL** | 안전장치 무력화 |
| in-flight · `mission_upload` | 조건부(항로 변경) | **HITL** | 종심 이탈 위험 |
| any · `gnss_spoof` / `jam` | 논리가역·물리효과 비가역 가능 | **HITL + 물리 안전요원** | EKF 발산→실제 거동 |
| read (`recon_heartbeat`/`param_read`) | 가역 | none | 상태 불변 |

### 4.2 3중 물리 안전 방어
1. **라이브 재분류** — 실행 tick에 독립 오라클로 상태 재취득 후 재분류(TOCTOU 차단, 캐시 금지).
2. **TOCTOU fail-closed** — 계획 tier가 조작·stale여도 라이브가 physical_irreversible면 토큰 요구.
3. **단발 토큰** — HITL 승인 시에만 노드 바인딩·만료 토큰 발급, executor가 소비. 없으면 거부.
   `risk_tier` 문자열 검사에만 의존하지 않는 2중 방어(`engagement/gate.py` issue/consume).

측정 가능한 불변식: **물리 비가역이 무단으로 실집행된 횟수 = 0** (하드코딩 아니라 오라클 전/후
비교로 계수 — 회귀로 뚫리면 실제로 잡힘, §10 ablation이 이 게이트가 2건 차단함을 계량).

### 4.3 스테이징 능력 게이트
오프라인/공급망 액션(AML.T0020 `ml_poison_training`)은 런타임 SITL에서 집행 불가 → executor가
게이트에서 거부하고 **"능력 도달"만 기록**(물리 비가역의 reached-gate와 동형). 무기고엔 편입하되
커버리지에서 `staged(런타임 미검증)`로 정직 표기.

### 4.4 egress default-deny
`safety/egress.py` — `ipaddress`로 scope CIDR(`10.50.0.0/24`) 검증, 파싱 실패 fail-closed.
scope 밖 표적은 송신 전 차단.

### 4.5 killswitch는 봉쇄가 아니다
`safety/killswitch.py`는 소프트 best-effort — `RTL(20)`/`LAND(21)` 송신. **단 봉쇄 아님**: RTL은
건강한 GPS/EKF·home 필요 → S1(GNSS 스푸핑)·JAM 하에선 실패 가능하고, 명령이 공격당하는 같은
링크로 나간다. **진짜 봉쇄 = 물리 out-of-band**(안전요원 + HW flight-termination + sim geofence).

---

## 5. 능력 평면 (scaffold) — 커버 100%

각 평면은 **동형 3계층 분리**(오라클/표적보고/전송)를 갖춘다. 표적 보고(ACK)는 위조 가능,
판정은 오라클(§6). 원자 액션 22개가 ATT&CK/ATLAS 기법 23종을 커버한다.

| 평면 | 기법 | 하드닝(PoV) 방어 | 코드 |
|---|---|---|---|
| **물리 MAVLink** | set_mode, force_arm, takeoff, disarm, mission_upload, param_set_safety, flight_terminate (T1692.001·T0836·T0838·T0821·T0831·T0827·T0880) | MAVLink2 서명(D3-MAN) | `tools/sitl_stub.py` |
| **RF/GNSS** | gnss_spoof(T0835·T0832), jam(T0814) | 다중센서 융합·항재밍(D3FEND 미커버=탐지격차) | `tools/sitl_stub.py` |
| **온보드 AI (ATLAS)** | ml_craft(T0043)→ml_evade(T0015), ml_prompt_inject(T0051)→ml_extract_secret(T0057) | 적대적 견고 모델·가드레일·출력필터 | `tools/ml_target.py` |
| **잔여 ICS** | active_scan(T1595), c2_common_port(T0885), unauthorized_command(T0855), spoof_telemetry(T0856), disable_protection(T0837), satcom_mitm(T0830·T0831) | 서명·망분리·파라미터잠금·링크암호화 | `tools/ics_actions.py` |
| **스테이징(오프라인)** | ml_poison_training(AML.T0020) | — (런타임 검증 불가, §4.3) | `tools/ml_target.py` |

**커버리지 표기 정직성**(`intel/catalog.py`): 무기고 커버 **100%**(23/23)지만 **런타임검증 95.7%**
(22/23) — AML.T0020만 `staged`. "검증 못 하는 능력은 주장하지 않는다."

---

## 6. 검증 (oracle) — ACK≠state

`SimGroundTruth`(공격 경로 밖 Gazebo/HIL)가 root-of-trust. `TargetTelemetry`/ACK는 untrusted.
validator는 **"믿는 값 vs 실제 값의 괴리"** 로 판정(내부 분산값이 아니라):
- 성공한 스푸핑/MITM은 조용히 틀어놓으므로, ACK=ACCEPTED여도 오라클 불일치면 **오탐 회피**로 계수.
- S1 gnss_spoof: 성공=드론이 *믿는* 위치가 진짜와 괴리(`drift > target_drift_m`). 분산 상승은
  '탐지가능성'일 뿐 성공 기준 아님.
- S3 satcom_mitm: MAVLink 아닌 satcom 평면(`IntegrityStatus≠ok`·seq 점프·session 변경)에서 검증.
- ml_leak: 유출 콘텐츠가 실제 시크릿과 불일치(디코이)면 미검증.

**PoV 페어 벤치마크**(`benchmarks/`): 8 그룹(A4/S1/M1/M2/R1/E1/I1/L1) × vuln↔hardened.
회귀 게이트 G1~G4: 안전위반=0 · 무회귀 · **PoV 일관(vuln 성공 ∧ hardened 거부)** · ASR(vuln)=1.0.
실 SITL 연동은 `range_mode: sitl|hil|live`로 `mavlink_adapter.py`(pymavlink 3-seam)에 스왑.

---

## 7. 학습 (메모리 기반 — 재학습 아님)

**모델 가중치 재학습 없음.** 오라클 검증된 경험을 쌓아 다음 engagement 행동을 바꾸는
온라인 신념 갱신이다.

### 7.1 저장 (서명·게이트)
- **TargetProfile**(B7): per-target 관측방어·시도기법·kill_chain(캡20)·**pb_scores**(액션→
  `{avg_effect, n}` 러닝평균). SHA-256 서명, 변조 시 읽기 거부.
- **ExperienceRecord**(B6): `(target,technique,action,verdict,effect,provenance,signature)`.
  단일 쓰기 게이트가 오염 방지: INCONCLUSIVE 폐기 · suppression(FAIL)은 신뢰 provenance만 ·
  fingerprint dedup · 비대칭 신뢰 회수.

### 7.2 갱신 (B8 + 영속)
`learn_from_state`가 **오라클 verdict**(자기보고 아님)를 fan-out. `pb_scores`는 재관측마다
`(avg·n+effect)/(n+1)`로 갱신. JSON 영속(`learning/persistence.py`)으로 프로세스·run 간 누적
(재적재 시 서명 재검증, 개별 불량 레코드만 스킵). CLI: `run.py --persist-learning DIR`.

### 7.3 계획 배선 (인과 lift) — 안전 우선
planner가 `recommend()`의 **trusted-FAIL 무익 액션만 스킵**(=미시도). 불변식:
- 빈 스토어 = 무영향(벤치 불변) · proven-wins(통한 액션 절대 스킵 안 함) · recon 불가침
- **무회귀**: 스킵은 이미-실패 액션만 → ASR 불변 · 게이트 우회 불가(스킵=미실행이라 더 안전)
- ablation 측정(§10): 재engagement에서 노출·예산 절감 → 학습이 "earns-keep".
- 설계 bound: 타깃 hardened→vuln 드리프트 시 stale skip 가능 → 리포트 명시(감사·가역)로 완화.

---

## 8. LLM seam + judge 앙상블 (조언 전용, veto 하)

- **기본 무-LLM**: `NullLLMClient`(네트워크 0, 항상 기권). `REDTEAM_LLM_PROVIDER`로만 opt-in
  (ollama/openai). urllib만(Tier-0), 비루프백 평문 HTTP fail-closed, 모든 실패 graceful-degrade.
- **judge 앙상블**(`judge/ensemble.py`): `SignalJudge`(오라클=**authoritative veto**) +
  `ExperienceJudge`(B6 사전지식) + `LLMJudge`(조언). **최종 verdict = 오라클, 항상.** LLM/경험은
  절대 못 뒤집음. 불일치만 표면화: `advisory_overclaim`(환각 성공 방어)·`covert_effect`(은밀 성공).
- **N-skeptic 패널**(D): LLM 판정을 온도 다양성(0.2→1.0) N표 + 엄격 다수결(votes×2>total)로
  강건화. panel=1이면 단일(하위호환), 기본 3(`settings.llm_judge_panel`). LLM 미활성이면 비용 0.
- **간접 프롬프트 인젝션 하드닝**(C, `judge/sanitize.py`): 표적 보고 증거를 프롬프트 진입 전
  중립화 — **NFKC 선-정규화**(전각 호모글리프 우회 차단)·역할마커/오버라이드/탈옥/코드펜스 중립화·
  구분자 격리. 인젝션 시도는 리포트에 관측 신호로 표면화(탐지 못 하면 undercount 아님).

---

## 9. OPSEC 스텔스 예산 (공격측 자기지식)

`opsec.py` — 실집행 액션의 **예상 탐지 노출**을 누적(blind_spot=D3FEND 미커버=은밀=낮은 노출,
관측가능=높은 노출). 스텔스 레벨(silent/covert/loud) 예산 초과 시 abort 권고. 조언 전용
(파이프라인 미변경). **D8 준수**: SOC 내부 미참조, "내 액션이 emit할 신호"라는 공격측 추론만.

---

## 10. 정직성·무결성 가드

| 가드 | 코드 | 역할 |
|---|---|---|
| **verify_claims** | `benchmarks/verify_claims.py` | 문서의 모든 수치를 committed 아티팩트에서 **재파생** + anti-fitting(오라클에 시나리오ID 하드코딩 금지) + fabrication 필터. 현재 **11 주장 전부 재파생 통과** |
| **회귀 게이트** | `benchmarks/check_gates.py` | G1~G4(안전=0·무회귀·PoV일관·ASR=1.0), CI 머지 차단 |
| **ablation** | `benchmarks/ablate.py` | 컴포넌트 **인과기여 계량**(오라클 9 FP 방지·토큰게이트 2 차단·학습 earns-keep) |
| **no-phantom** | `tests/test_no_phantom_action.py` | "advertised=wired" — MAP/playbook 액션이 실제 실행가능한지(⚡`satcom_mitm` phantom 적발 이력) |
| **시크릿 redaction** | `safety/redact.py` | 유출 시크릿을 fingerprint로 치환(원문 미기록), `secret_captured` 신호만 |

---

## 11. 탐지 계약 — 공격 → ATT&CK-ICS → 예상 로그 → D3FEND (내장)

**에이전트는 SOC와 코드 결합하지 않는다(D8).** 아래 표가 **유일한 다리** — 각 원자 액션이
*예상 탐지 시그니처*(관측 로그 `UAV*_CL` 테이블, PascalCase Sentinel 스키마)와 *D3FEND 처방*을
동반한다. Reporter가 이 표로 "탐지격차 → 방어 산물"을 산출(공격→방어 distillation, 2602.02595).
매핑 로직은 `mapping/attack_d3fend.py`.

| 레드팀 원자 액션 (시나리오) | ATT&CK-ICS | 예상 `UAV*_CL` 시그니처 (탐지 가설) | D3FEND 처방 |
|---|---|---|---|
| 무인증 5790 접속 (A4 진입) | T1694 / T0840 | `UAVDatalinkConn_CL` LocalPort=5790·PeerIp∉known / `UAVRouterStats_CL` CrcErrors↑ | **Isolate** D3-NI·**Harden** D3-CH/D3-ACH·**Detect** D3-NTA |
| `force_arm` 주입 (A4) | T1692.001 / T1106 | `UAVOperator_CL` SourceSystemId∉{1,254,255}·Command=400·Param1=1 | **Harden D3-MAN**(서명)·Isolate D3-CF·Detect D3-NTA |
| `set_mode` GUIDED 강제 (A4) | T1692.001 | `UAVOperator_CL` Command=176·SourceSystemId∉allow / `UAVTelemetry_CL` CustomMode 델타 | **D3-MAN**·D3-CF·D3-NTA |
| `param_set_safety` (ARMING_CHECK/FS_*) | T0836 / T0838 | `UAVConfigAudit_CL` ParamId=ARMING_CHECK/FS_*·ParamValueAfter=0 | **Harden D3-ACH**·D3-MAN·Isolate D3-APA |
| `mission_upload` (항로 탈취) | T0821 | `UAVConfigAudit_CL` ParamId / `UAVMissionEvent_CL` 비정상 Seq | D3-ACH·**D3-MAN**(서명 임무) |
| `disarm`(비행중) / `flight_terminate` | T0831→T0827 | `UAVFailsafe_CL` ModeAfter / `UAVTelemetry_CL` SystemStatus 급변 | D3-MAN·**Isolate D3-APA**(2인통제)·D3-ACH |
| **`gnss_spoof`** (S1) | T0835 (+T0832) | `UAVTelemetry_CL` PosHorizVariance>0.5·FixType↓ (탐지가능 신호; 성공 판정은 §6 괴리 기준) | **D3FEND 미커버 → custom**(다중센서 융합·항스푸핑) |
| **`satcom_mitm`** (S3) | T0830 / T0831 | `UAVSatcomLink_CL` IntegrityStatus≠ok·Seq 점프·SessionId 급변 | **Harden** D3-MAN·D3-MENCR · **Isolate D3-ET**(링크 암호화/터널) |
| **`jam`** (JAM) | T0814 | `UAVDatalink_CL` RxDropped↑ / `UAVSatcomLink_CL` JamIndicator↑ | **D3FEND 미커버 → custom**(항재밍·링크 다중화) · Isolate D3-NI |
| `disable_protection` (Loss of Protection) | T0837 | `UAVFailsafe_CL` EventType / `UAVConfigAudit_CL` ParamId | **Harden** D3-ACH · **Isolate** D3-APA |
| `spoof_telemetry` (Manipulation of View) | T0856 / T0832 | `UAVTelemetry_CL` PosHorizVariance / `UAVSatcomLink_CL` IntegrityStatus | **Detect** D3-NTA · **Harden** D3-MAN |
| `c2_common_port` (C2 유지) | T0885 | `UAVDatalinkConn_CL` LocalPort·PeerIp | **Detect** D3-NTA · **Isolate** D3-NI |
| `active_scan` (recon) | T1595 | `UAVDatalinkConn_CL` LocalPort·PeerIp | **Detect** D3-NTA (예방=네트워크 격리) |
| ml_craft→ml_evade (ATLAS) | AML.T0043→T0015 | (온보드 AI 평면 — sim 인지 결과 괴리) | 적대적 견고 모델·출력필터 |
| ml_prompt_inject→ml_extract_secret | AML.T0051→T0057 | (프롬프트 인젝션 시도 신호) | 가드레일·입력 새니타이즈 |
| ml_poison_training (스테이징) | AML.T0020 | — (오프라인, 런타임 미검증 §4.3) | 데이터 출처 검증·서명 |

> **사각지대 우선(§1.8) 결론:** D3FEND 미커버(S1·JAM)·무서명 인젝션(A4)이 **탐지격차 1순위**.
> Reporter는 "D3-MAN 서명 적용 + RF/GNSS 커스텀 대응"을 핵심 방어 권고로 산출한다. D3FEND
> v1.4.0 전술 표기 주의: `D3-ET`(링크 암호화/터널)는 **Isolate**(Harden 아님), D3-MAN·D3-MENCR은
> Harden.
>
> **ID 표기 주의**: (1) 비인가 명령 주입은 프로젝트 표준 **`T1692.001`**(MITRE historical
> `T0855`와 동일 행위; 카탈로그는 두 ID 모두 보유). (2) S1 GNSS는 `T0835 Manipulate I/O Image`
> (T0830은 SATCOM S3에 배정).

---

## 12. SOC와의 관계 — 단방향 브릿지 (D8)

`bridge/telemetry_tap.py` + `soc_feeder.py`가 **자기 audit_log**에서 `UAV*_CL` 행 + `soc_alert.json`
을 재구성(관측자 계약). `run.py --emit-soc` → `out/`. **pollack-ai를 import/수정하지 않음** —
공격→(로그)→방어 한 방향뿐. 코드 결합·라이브 연동 없음.

---

## 13. 테스트·CI

- **182 tests**(16 파일) — 안전 라우팅 회귀 그물 + 능력 평면 오라클 매트릭스 + PoV + 학습 +
  judge/인젝션 + 영속/어댑터 + OPSEC + ablation + no-phantom + redaction.
- **CI**(`.github/workflows/ci.yml`): pytest → `check_gates --run` → `verify_claims` → gitleaks.
- 전부 결정론·오프라인(Tier-0). LLM·실 SITL은 선택적 seam이라 CI 무의존.

---

## 14. 파일 지도

```
redteam_core/
  engagement/   gate.py(비-LLM: scope/sysid allowlist·예산·토큰 발급정책)
  graph/        state.py(PTG 스키마) + build.py(LangGraph/stdlib 러너)
  nodes/        파이프라인 노드 11개(recon…reporter)
  safety/       reversibility·hitl_gate·egress·killswitch·toolparse·channels·redact
  tools/        sitl_stub·mavlink·ml_target·ics_actions·mavlink_adapter·range_factory·gazebo_backend
  mapping/      attack_d3fend(ATT&CK-ICS/ATLAS→UAV*_CL→D3FEND)
  learning/     target_profile·experience·outcome·fingerprint·persistence (B6~B8)
  judge/        ensemble(SignalJudge veto·ExperienceJudge·LLMJudge 패널)·sanitize
  llm/          client·factory(선택적 조언 seam)
  intel/        attack/atlas/kev 피드·catalog(커버리지)·refresh
  memory/       TypedMemory(episodic/semantic/procedural)
  bridge/       telemetry_tap·soc_feeder(단방향 SOC 브릿지)
  eval/         scorecard(마일스톤·per-run·물리안전위반율)
  opsec.py      스텔스 노출 예산   settings.py 중앙 설정   session.py   logging_util.py
benchmarks/     harness·check_gates·verify_claims·ablate·run_attack_eval
run.py demo.py  엔트리포인트   engagement_profile.yaml (+ .sitl-local.yaml)
```

---

## 15. 설계원문 §-크로스워크 (코드 주석 참조 해소)

코드 주석은 외부 설계원문의 `§`-번호를 인용한다. 저장소 자립성을 위해 각 §를 **이 문서
내부 절**로 매핑한다. (원문 Part 1=설계 §1.x, Part 2=구현 §2.x.)

| 원문 § | 주제 | 이 문서 위치 |
|---|---|---|
| §1.0 | 표적 도메인 모델(토폴로지·통찰4) | **§0** |
| §1.2 | 공격면 테이블 | **§0.1** |
| §1.3 | 12-컴포넌트 참조 아키텍처 | **§3**(파이프라인)·§1 |
| §1.4 | 컴포넌트 카드(Gate·Recon·Validator·HITL·Reporter) | **§3**·§4·§6 |
| §1.5 | 킬체인 → ATT&CK-ICS 전술 경로 | **§11**(탐지 계약) |
| §1.6 | 추상 액션 ↔ HITL 분리 | **§3.1** |
| §1.7 | 가역성 결정 테이블 | **§4.1** |
| §1.8 | 사각지대 우선 레버 | **§11** 결론 |
| §2.2 | RedTeamState / PTG 스키마 | `graph/state.py` + §3 |
| §2.3 | 타입화 메모리 | **§7** + `memory/typed_memory.py` |
| §2.4 | MAVLink 툴 스키마(think-augmented) | **§3**(synth/checker) + `tools/mavlink.py` |
| §2.5 | LangGraph 그래프·라이브 재분류·토큰 | **§3**·**§4.2** |
| §2.6 | Engagement Gate(비-LLM·토큰) | **§4.2·§4.4** + `engagement/gate.py` |
| §2.7 | Validator 신뢰근거 오라클 | **§6** |
| §2.8 | 안전 게이트 구현(killswitch·toolparse·channels) | **§4.5·§8** |
| §2.9 | 평가 하네스·PoV·스코어카드 | **§6**·§13 + `benchmarks/`·`eval/` |

> 완전 자립을 위해 설계원문 전체가 필요하면, **개인정보 스캔 후** `docs/DESIGN.md`로 편입을
> 검토한다(현재는 위 크로스워크로 충분 — 모든 §-참조가 저장소 안에서 해소됨).
