"""아카이브 경로순회 생성·탐지 테스트 — S39~S41 + §T. 결정론·무의존."""
from __future__ import annotations

import io
import zipfile

from redteam_core.payloads import (
    craft_zip_slip, craft_zip_absolute, craft_tar_symlink, craft_tar_slip,
)
from redteam_core.sandbox import detonate_archive


def test_zip_slip_detected_malicious():
    p = craft_zip_slip("../../../opt/uav/startup.d/rogue.sh")
    r = detonate_archive(p.data, "zip")
    assert r.verdict == "malicious"
    assert any(".." in e for e in r.escaping)
    assert r.contained is True                    # 실제 밖 쓰기 없음


def test_zip_absolute_path_detected():
    p = craft_zip_absolute("/etc/cron.d/rogue")
    r = detonate_archive(p.data, "zip")
    assert r.verdict == "malicious" and any(e.startswith("/") for e in r.escaping)


def test_tar_symlink_escape_detected():
    p = craft_tar_symlink("link", "/etc", "link/rogue")
    r = detonate_archive(p.data, "tar")
    assert r.verdict == "malicious"
    assert any("symlink 탈출" in e or e.startswith("link") for e in r.escaping)


def test_tar_slip_overwrites_param():
    p = craft_tar_slip("../../../opt/uav/param/BRD_SAFETYENABLE")
    r = detonate_archive(p.data, "tar")
    assert r.verdict == "malicious"


def test_benign_archive_passes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("firmware.bin", b"ok")
    r = detonate_archive(buf.getvalue(), "zip")
    assert r.verdict == "benign" and r.escaping == []


def test_decoy_entry_present_but_only_traversal_flagged():
    p = craft_zip_slip()
    r = detonate_archive(p.data, "zip")
    assert "manifest.json" in r.entries and "manifest.json" not in r.escaping
