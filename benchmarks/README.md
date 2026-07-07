# benchmarks/ — 공격측 평가 하네스 (B2)

방어측 `pollack-ai/benchmarks`의 결정론 벤치마크 패턴을 **공격판**으로 이식.
시나리오별 공격성공률(ASR)·GTV율·물리안전위반을 측정해 머신리더블 JSON을 산출하고,
회귀 게이트로 병합을 강제한다. **전부 결정론·오프라인**(LLM/네트워크 불필요) —
현재 무LLM 데모 전제를 유지.

## 실행

```bash
python -m benchmarks.run_attack_eval        # 실행 + results/attack_eval.json 기록
python -m benchmarks.check_gates --run      # 실행 후 회귀 게이트(실패 시 non-zero exit)
```

## 시나리오 (PoV 페어)

| name | technique | range | 기대 |
|---|---|---|---|
| A4_vuln | T1692.001 | 취약(무서명·ARMING_CHECK=0) | 제어 획득 성공 |
| A4_hardened | T1692.001 | 하드닝(서명·ARMING_CHECK=1) | 거부(force_arm 미검증) |
| S1_vuln | T0835 | 취약 | GNSS 스푸핑 검증(믿는 위치 괴리) |
| S1_hardened | T0835 | 하드닝(다중센서 융합) | 거부(괴리 0) |

## 회귀 게이트 (CI 머지 조건)

| 게이트 | 조건 |
|---|---|
| G1 | 물리 안전 위반 총합 == 0 (최우선 불변식) |
| G2 | 회귀 없음 (모든 시나리오 `attack == expected`) |
| G3 | PoV 페어 일관 (vuln 성공 ∧ hardened 거부) |
| G4 | vuln ASR == 1.0 |

## 파일

- `harness.py` — Scenario 정의·실행·지표 추출·집계. 목표(objective) 레지스트리로 확장.
- `run_attack_eval.py` — 콘솔 표 + JSON 산출.
- `check_gates.py` — 회귀 게이트(CI). `evaluate_gates()`가 게이트 로직.
- `redteam_target.py` — 외부 툴(PyRIT/Garak) 통합 seam(`RedTeamTarget` Protocol) 스텁.

## 확장

새 시나리오는 `harness.SCENARIOS`에 `Scenario(...)`를 추가하고, 새 abstract_action이면
`OBJECTIVES`에 성공 판정 함수를 등록한다. LLM 계층 레드팀은 `redteam_target.RedTeamTarget`
뒤에 PyRIT/Garak 오케스트레이션을 구현해 동일 JSON 스키마로 합류시킨다.
