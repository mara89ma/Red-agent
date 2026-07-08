"""sandbox — 악성코드 detonation 샌드박스 (고도화 §T, opt-in).

실 도구 실행(§Q Caldera/PyRIT)·실 임플란트(§L)·유출 페이로드를 **격리 환경에서
안전하게 폭파(detonate)**해 행위를 관측한다. 결정론 기본(sim): 임시 FS 격리+롤백 +
egress default-deny(스코프 밖 차단) + 악성 지표 판정. `SANDBOX_BACKEND=docker` +
env 지정 시에만 실 격리 컨테이너(네트워크 격리·스냅샷 롤백)로 실행(라이브 seam).

안전: 실 표적/호스트에 영향 없음. egress 는 스코프(engagement_profile scope_cidr)
allowlist 로만 허용, 나머지 차단·기록. FS 는 ephemeral tempdir + rollback.
"""
from .detonate import DetonationReport, DetonationSandbox, SandboxPolicy
from .guard import ai_spec, caldera_spec, default_policy, guard, guarded

__all__ = ["DetonationReport", "DetonationSandbox", "SandboxPolicy",
           "ai_spec", "caldera_spec", "default_policy", "guard", "guarded"]
