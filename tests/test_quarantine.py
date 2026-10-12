"""glove/quarantine.py: the macOS quarantine stamp on what sidecars saved."""

from __future__ import annotations

import os
import subprocess
import sys

from helpers import darwin
from helpers import quarantine_attr as _attr

from glove import quarantine


@darwin
def test_files_and_dirs_are_stamped_once_and_links_never_followed(tmp_path):
    out = tmp_path / "downloads"
    (out / "sub").mkdir(parents=True)
    (out / "a.zip").write_bytes(b"x")
    (out / "sub" / "b").write_bytes(b"y")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "c").write_bytes(b"z")
    (out / "file-link").symlink_to(outside / "c")
    (out / "dir-link").symlink_to(outside)
    os.mkfifo(out / "fifo")

    r = quarantine.mark([out, tmp_path / "missing"])
    assert (r.stamped, r.already, r.failed) == (3, 0, [])
    assert _attr(out / "a.zip").startswith("0081;") and _attr(out / "a.zip").endswith(";glove;")
    assert _attr(out / "sub") and _attr(out / "sub" / "b")
    assert _attr(out) is None  # the output dir itself is the session's
    assert _attr(outside / "c") is None and _attr(outside) is None
    assert _attr(out / "file-link") is None and _attr(out / "dir-link") is None

    subprocess.run(["xattr", "-w", "com.apple.quarantine", "00c1;0;Finder;", str(out / "a.zip")], check=True)
    (out / "new").write_bytes(b"n")
    r = quarantine.mark([out])
    assert (r.stamped, r.already) == (1, 3)
    assert _attr(out / "a.zip") == "00c1;0;Finder;"  # an approval the operator gave stays


@darwin
def test_a_linked_output_dir_is_not_walked(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "f").write_bytes(b"x")
    (tmp_path / "downloads").symlink_to(tmp_path / "real")
    assert quarantine.mark([tmp_path / "downloads"]).stamped == 0


def test_off_macos_nothing_is_touched(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    (tmp_path / "f").write_bytes(b"x")
    assert not quarantine.supported() and quarantine.mark([tmp_path]).stamped == 0


@darwin
def test_a_directory_swapped_for_a_link_mid_walk_is_not_followed(tmp_path, monkeypatch):
    # a running sidecar replaces downloads/sub/ with a link after the walk listed it
    out, outside = tmp_path / "downloads", tmp_path / "outside"
    (out / "sub").mkdir(parents=True)
    outside.mkdir()
    (outside / "victim").write_bytes(b"v")
    real_fwalk = os.fwalk

    def racing_fwalk(top, *a, **k):
        for i, entry in enumerate(real_fwalk(top, *a, **k)):
            yield entry
            if i == 0:
                (out / "sub").rmdir()
                (out / "sub").symlink_to(outside)

    monkeypatch.setattr(quarantine.os, "fwalk", racing_fwalk)
    r = quarantine.mark([out])
    assert _attr(outside / "victim") is None and _attr(outside) is None
    assert r.stamped == 1  # the real sub/, before the swap
