"""Egress 실통제 (§2.6 — 프롬프트가 아니라 네트워크 계층에서 강제).

default-deny + scope_cidr allowlist를 **OS 방화벽**(nftables/iptables)으로 설치한다.
root가 아니거나 방화벽이 없으면 `simulated` 모드로 강등하되, 애플리케이션 계층
가드(`allowed()`)는 항상 fail-closed로 작동한다 — Executor/Transport가 송신 전
호출해 scope 밖 IP를 차단.

안전: 파괴적 규칙을 함부로 설치하지 않는다. 실제 설치는 root + apply=True 일 때만.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class EgressController:
    scope_cidr: list
    mode: str = "uninitialized"          # installed | simulated | uninitialized
    intended_rules: list = field(default_factory=list)

    def allowed(self, ip: str) -> bool:
        """애플리케이션 계층 fail-closed 가드. scope_cidr 밖이면 False.

        CIDR 마스크를 실제로 존중한다(`ipaddress` 네트워크 포함 검사) — 앞 3옥텟만
        비교하던 과거 구현은 /24가 아닌 scope에서 조용히 오작동했다. 파싱 불가한
        IP나 잘못된 CIDR은 매칭에서 제외되어 default-deny로 귀결된다.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False                 # 파싱 불가 표적 IP → fail-closed
        for cidr in self.scope_cidr:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue                 # 잘못된 CIDR 항목은 무시(허용으로 새지 않음)
            if addr.version == net.version and addr in net:
                return True
        return False

    def enforce(self, apply: bool = False) -> "EgressController":
        """default-deny + allowlist 규칙을 구성. root+apply면 실제 설치, 아니면 시뮬레이트."""
        self.intended_rules = ["OUTPUT policy DROP (default-deny)"]
        self.intended_rules += [f"ALLOW OUTPUT -> {c}" for c in self.scope_cidr]
        self.intended_rules.append("ALLOW OUTPUT -> lo")

        can_apply = apply and hasattr(os, "geteuid") and os.geteuid() == 0
        backend = "nft" if shutil.which("nft") else ("iptables" if shutil.which("iptables") else None)

        if can_apply and backend:
            try:
                self._apply(backend)
                self.mode = "installed"
                return self
            except Exception:
                self.mode = "simulated"     # 설치 실패 시 안전하게 강등
                return self
        # 비-root / 방화벽 없음 / apply=False → 시뮬레이트(앱 계층 가드가 대신 강제)
        self.mode = "simulated"
        return self

    def _apply(self, backend: str) -> None:  # pragma: no cover - root 환경 전용
        if backend == "nft":
            subprocess.run(["nft", "add", "table", "inet", "redteam_egress"], check=True)
            subprocess.run(["nft", "add", "chain", "inet", "redteam_egress", "out",
                            "{ type filter hook output priority 0 ; policy drop ; }"], check=True)
            subprocess.run(["nft", "add", "rule", "inet", "redteam_egress", "out",
                            "oifname", "lo", "accept"], check=True)
            for c in self.scope_cidr:
                subprocess.run(["nft", "add", "rule", "inet", "redteam_egress", "out",
                                "ip", "daddr", c, "accept"], check=True)
        else:  # iptables
            subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
            for c in self.scope_cidr:
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", c, "-j", "ACCEPT"], check=True)

    def status(self) -> dict:
        return {"mode": self.mode, "scope_cidr": self.scope_cidr, "rules": self.intended_rules}
