# fried-pollack-ai — UAV 대상 AI 레드티밍 에이전트

> 방산 **UAV 시뮬레이션 환경 `uav-sim-env`(KUS-FS급 MUAV)** 를 표적으로 하는 공격 측
> 자율·반자율 AI 레드팀 에이전트의 **참조 구현**.

**한 줄 논지**: 물리 비가역 명령의 판정 권한은 모델 밖(결정론 게이트 + out-of-band 오라클)에
있어야 안전하다. → LLM ReAct 자율 루프를 **의도적으로 피하고**, 결정론 파이프라인 + 조언 전용
LLM(오라클 veto 하) + 메모리 기반 학습으로 구성.

**규모**: Python 모듈 68 · 원자 액션 22 · 무기고 커버 **23/23=100%**(런타임검증 95.7%, AML.T0020
스테이징) · 벤치 16 시나리오/**8 PoV 페어** · **182 tests green** · Tier-0(무의존 실행).

## 📚 저장소 자립 문서 (클론 하나로 완결 — 외부 파일 의존 없음)

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — 전체 아키텍처(표적 도메인 모델·세 기둥·불변식·
  파이프라인·능력 평면·학습·judge·OPSEC·정직성 가드·**탐지 계약 내장**·설계원문 §-크로스워크).
- **[REFERENCES.md](REFERENCES.md)** — 참고 논문 17편 + 이식 출처(pollack-ai 역전·T3MP3ST)를
  각 설계결정·코드 위치에 매핑 + 탐지 계약 요지.
- [SETUP.md](SETUP.md) · [benchmarks/README.md](benchmarks/README.md)

> 과거 저장소 밖에 있던 설계원문·탐지계약(ATT&CK-ICS→UAV*_CL→D3FEND)은 **ARCHITECTURE.md §11·§15
> 와 REFERENCES.md §3에 내장**돼, 이제 클론만으로 모든 `§`-참조가 해소된다.

---

## 세 기둥

| 기둥 | 의미 | 코드 위치 |
|---|---|---|
| **scaffold = 능력** | 능력은 모델 크기가 아니라 루프 전체(PTG·추상액션·메모리)에서 나온다 | `graph/`, `nodes/planner.py`, `rag/playbook.py` |
| **오라클 = 진위** | 오탐 제거는 토폴로지가 아니라 독립 검증 오라클(ground truth)이 정한다 | `nodes/validator.py`, `tools/sitl_stub.py`, `tools/gazebo_backend.py` |
| **게이트 = 안전** | 물리 비가역 차단은 별도 HITL 게이트로 항상 작동(토폴로지와 직교) | `safety/`, `engagement/gate.py` |

## 능력 평면 · 정직성 가드 (요약 — 상세 [ARCHITECTURE.md](ARCHITECTURE.md))

- **능력 평면 4종 + 스테이징**: 물리 MAVLink(arm/mode/takeoff/mission/param/flight-term) · RF/GNSS
  (`gnss_spoof`/`jam`) · **온보드 AI(ATLAS)**(ml_craft→evade, prompt_inject→extract) · 잔여 ICS
  (scan/c2/unauth_cmd/spoof_tlm/disable_protection/satcom_mitm) · 스테이징(ml_poison_training,
  런타임 미검증). 원자 액션 22개가 ATT&CK/ATLAS 기법 23종 커버.
- **judge 앙상블**(`judge/ensemble.py`): 오라클=authoritative veto + Experience + LLM 조언, N-skeptic
  패널(온도 다양성·엄격 다수결), 간접 프롬프트 인젝션 하드닝(NFKC 선정규화, `judge/sanitize.py`).
- **학습**(재학습 아님): 오라클 검증 경험을 서명·게이트로 축적(`learning/`) → planner가
  trusted-FAIL 무익 액션만 스킵(무회귀 보장). `run.py --persist-learning DIR`로 run 간 누적.
- **OPSEC**(`opsec.py`): 실집행 액션의 예상 탐지 노출 예산(공격측 자기지식, 파이프라인 미변경).
- **정직성 가드**: `verify_claims.py`(문서 수치 committed 아티팩트 재파생, **11 주장 통과**) ·
  `check_gates.py`(G1~G4 CI 차단) · `ablate.py`(컴포넌트 인과기여 계량) · no-phantom 가드 ·
  시크릿 redaction. CI: pytest → check_gates → verify_claims → gitleaks.

## 안전 전제

전 과정은 **격리 SITL/HIL 레인지 · 완전 인가** 하에서만 수행한다. GNSS/RF 송신은
차폐(Faraday) 또는 `gps-sdr-sim` 파일 주입/SITL GPS 백엔드로 한정한다(공중 송신은
대부분 관할권에서 위법). 물리 비가역 명령(비행 중 disarm·flight-termination·takeoff)은
**인간 전용** 이며, 이 구현은 그것을 자동 실행하지 않는다.

---

## 빠른 시작

```bash
python run.py                 # A4 킬체인 실행(스텁 레인지) — 설치 불필요(stdlib)
python run.py --emit-soc      # + ③ 브릿지: 관측 트래픽 → UAV*_CL + SOC Alert (out/)
python run.py --json          # 전체 리포트 JSON
python demo.py                # 서사형 데모(스토리라인 출력)
```

**기본 러너 = LangGraph**(`interrupt` 기반 HITL + 체크포인트). `pip install langgraph`면
그래프가 고위험/물리 비가역 명령 앞에서 **실제로 일시정지**하고, 운용자 승인이
`resume`될 때까지 대기한다. langgraph 미설치 시 **동일 라우팅의 순수 stdlib 러너로
자동 강등**되어 아무 설치 없이도 돈다(단, interrupt 일시정지 대신 동기 콜백 HITL).

Tier 0는 **설치 없이도 지금 즉시** 돈다. 실 MAVLink 트래픽·Gazebo·방화벽·SOC
폐루프는 필요한 만큼만 올린다 → **[`SETUP.md`](SETUP.md)** (Tier 0~4 전체 절차).

### run.py 옵션

| 옵션 | 효과 |
|---|---|
| `--profile <path>` | 프로파일 지정 (기본 `engagement_profile.yaml`) |
| `--range-mode container\|sitl\|hil\|live` | 레인지 모드 오버라이드 |
| `--hardened` | 하드닝 인스턴스(PoV 페어 비교: 취약 성공 / 하드닝 거부) |
| `--emit-soc` | ③ 브릿지 산출(`out/uav_cl_rows.ndjson`, `out/soc_alert.json`) |
| `--apply-egress` | egress default-deny를 OS 방화벽(nft/iptables)에 실제 설치(root) |
| `--json` | 전체 리포트 JSON 출력 |

모든 환경 정보(range_mode·target·observables·sim)는 **YAML 프로파일**에서 온다(코드 하드코딩 금지).

---

## 파일 구성

```
fried-pollack-ai/
├─ run.py                          # 엔트리포인트 (argparse CLI)
├─ demo.py                         # 서사형 데모
├─ engagement_profile.yaml         # 기본 프로파일 (container/스텁)
├─ engagement_profile.sitl-local.yaml  # 로컬 SITL 프리셋 (range_mode: sitl, Gazebo 불필요)
├─ requirements.txt                # pip 의존성(계층별) + pip 불가 인프라 명시
├─ SETUP.md                        # 설치·설정·실행 런북 (Tier 0~4)
└─ redteam_core/
   ├─ engagement/gate.py           # (0) 비-LLM: scope/sysid allowlist·예산·물리비가역 토큰·egress
   ├─ graph/state.py               # RedTeamState·PTGNode(안전 메타 보유)
   ├─ graph/build.py               # StateGraph 와이어링 + route_to_hitl + 순수 stdlib 러너
   ├─ nodes/                       # recon·planner·synthesizer·checker·broker·executor·
   │                               #   summarizer·validator·reflection·reporter
   ├─ tools/mavlink.py             # 원자 액션 스키마(ATOMIC_ACTIONS), think-augmented 명령
   ├─ tools/sitl_stub.py           # 인메모리 SITL 스텁(ground truth + untrusted 텔레메트리)
   ├─ tools/mavlink_adapter.py     # 실 pymavlink 3-seam(쓰기/관측/진위) — sitl|hil|live
   ├─ tools/gazebo_backend.py      # Gazebo 물리 pose = 물리 root-of-trust
   ├─ tools/range_factory.py       # range_mode → 스텁 ↔ 실 어댑터 자동 스왑
   ├─ tools/{ml_target,ics_actions}.py  # 온보드 AI(ATLAS) 평면 + 잔여 ICS 액션
   ├─ rag/{static_kb,playbook}.py  # 2종 RAG(스펙 / 검증 킬체인) — 둘 다 untrusted
   ├─ memory/typed_memory.py       # episodic / semantic(버전화) / procedural(효용 게이트)
   ├─ safety/reversibility.py      # 가역성 결정 테이블(라이브 상태 입력)
   ├─ safety/{hitl_gate,killswitch,toolparse,channels,redact}.py
   ├─ safety/egress.py             # default-deny OS 방화벽(nft/iptables) + 앱 계층 fail-closed
   ├─ judge/{ensemble,sanitize}.py # 오라클 veto judge 앙상블 + 간접 인젝션 하드닝
   ├─ learning/                    # target_profile·experience·outcome·fingerprint·persistence(B6~B8)
   ├─ intel/                       # attack/atlas/kev 피드 + catalog(커버리지)
   ├─ llm/{client,factory}.py      # 선택적 LLM 조언 seam(기본 NullLLMClient)
   ├─ opsec.py                     # 스텔스 탐지 노출 예산(공격측 자기지식)
   ├─ eval/scorecard.py            # 마일스톤·GTV율·물리안전위반율(=0 필수)
   ├─ mapping/attack_d3fend.py     # 공격→ATT&CK-ICS→예상 UAV*_CL→D3FEND
   └─ bridge/                      # ③ RedTeam↔SOC 다리: telemetry_tap(→UAV*_CL) + soc_feeder(→Alert)
```

---

## 파이프라인

```
profile → (0)Gate → recon → planner → synth → checker ─ok→ broker ─┬─auto──────────────┐
                                                    └violation→reflection   └needs_approval→hitl┤
                                                                              approved→ executor ┘
   executor → summarizer → validator → reflection ─┬─continue→ planner
                                                    ├─rescan→ recon
                                                    └─stop→ reporter → END (증거 + ATT&CK-ICS/D3FEND)
```

추상 액션(`hijack`)은 **계획 단위**로만 존재하고, planner가 원자 노드
(`set_mode → force_arm → takeoff`)로 전개한다. **게이트는 전개된 원자 노드마다·실행
직전·라이브 상태로** 작동한다.

### A4 킬체인 (기본 실행 결과)

```
n0 recon_heartbeat  success  read                    T0840
n1 set_mode         success  write_lowrisk           T1692.001
n2 force_arm        success  write_highrisk          T1692.001,T1106
n3 takeoff          blocked  physical_irreversible   T1692.001   ← 인간 전용 게이트 도달(실집행 X)
```

→ 무인증 5790 → **제어 획득**(set_mode+force_arm, ground truth 검증) → **미션킬 능력을
게이트 도달로 증명** · **물리 안전 위반율 0**. `--emit-soc`면 이 트래픽이 SOC가 삼킬
`UAV*_CL` 행 + Alert로 나온다.

---

## 실 레인지 연동 (range_mode: sitl|hil|live)

`tools/range_factory.py:make_range`가 `range_mode`를 보고 인메모리 스텁 ↔ 실 pymavlink
3-seam(`tools/mavlink_adapter.py`)을 **자동 스왑**한다. 노드 코드는 변경 없음(동일 인터페이스):

- **쓰기** `MavlinkTransport` → `datalink-los:5790` 실 MAVLink 인젝션
- **관측** `MavlinkTelemetry` → read-only 세션 (untrusted)
- **진위** `GroundTruthOracle` → **Gazebo 물리 pose(root-of-trust)** + SITL sim-state(논리 보조)

> **Gazebo는 선택이다.** ArduPilot SITL은 내장 물리로 단독 실행되므로 A4(논리 상태)는
> `backend: sim_state`로 SITL만으로 실증된다. Gazebo는 S1 GNSS 등 물리 시나리오의 진위를
> 진짜 out-of-band로 올릴 때만 추가. 최소 실동작 = `pip install pymavlink` + ArduPilot SITL
> + `python run.py --profile engagement_profile.sitl-local.yaml` (→ [`SETUP.md`](SETUP.md)).

---

## 3중 물리 안전 방어 (SOC Approval 게이트의 공격판)

`graph/build.py:route_to_hitl` — 판정·승인 권한을 결정론 규칙에 두고 LLM에 주지 않는다:

1. **라이브 재분류** — 실행 tick에 독립 오라클로 물리상태 재취득(계획 캐시 금지).
2. **TOCTOU fail-closed** — 계획 분류 ≠ 라이브 분류면 라이브로 갱신 후 재게이트.
3. **토큰 강제** — `physical_irreversible`은 Gate가 승인에 바인딩해 발급한 단발 토큰
   없이는 `executor`가 거부(`risk_tier` 문자열 검사에만 의존하지 않는 2중 방어).

여기에 **egress default-deny**(`safety/egress.py`)가 더해진다 — Executor는 송신 전
`gate.egress_allowed(target_ip)`로 scope 밖 표적을 차단(비-root면 simulated + 앱 계층 fail-closed).

---

## SOC와의 관계 (③ 브릿지)

RedTeam과 SOC는 **코드 결합하지 않는다**(공격자가 방어자 뇌에 못 씀). 유일한 다리는
`UAV*_CL` 로그 + SOC Alert다.

- `bridge/telemetry_tap.py` — 관측된 트래픽(audit_log) → `UAV*_CL` 행. 차단/거부된 액션은
  실제 송신이 없으므로 행을 만들지 않는다(예: 게이트에서 막힌 takeoff = 탐지 표면 없음).
- `bridge/soc_feeder.py` — `UAV*_CL` → SOC Alert 스키마.

탐지 계약(기법→테이블/컬럼, 정상 sysid `{1,254,255}` 등)의 전체 매핑(원자 액션→ATT&CK-ICS→
예상 `UAV*_CL` 시그니처→D3FEND 처방)은 **[ARCHITECTURE.md §11](ARCHITECTURE.md)에 내장**됐고,
요지는 [REFERENCES.md §3.2](REFERENCES.md)에 있다. 이 값들은 `engagement_profile.yaml`의
`observables:` 블록으로 외부화되어 있다.

---

## 의존성 한눈에

- **Tier 0(기본):** `langgraph`(기본 러너 = interrupt HITL, 없으면 stdlib 폴백) + `pyyaml`(선택).
- **Tier 1(실 MAVLink):** `pip install pymavlink` **+ ArduPilot SITL 기동** (가장 필수).
- **Tier 2(Gazebo):** `gz` 시스템 바이너리 — S1 물리 진위에만.
- **Tier 3(egress):** root + `nft`/`iptables` — `--apply-egress`에만.
- **Tier 4(SOC 폐루프):** SOC + Sentinel 워크스페이스.

> pip 설치만으로 "전부 동작"하지 않는다 — pip은 파이썬 라이브러리만 깐다. 상세: [`SETUP.md`](SETUP.md).
