"""Harness image tags follow what the image is built from: a changed base
context or harness release is a new tag, so neither the base nor any image
built on it is reused."""

from __future__ import annotations

import dataclasses
import shutil

from glove import session
from glove.harness import base_image, effective_image, get_profile


def _copy(tmp_path, name="pi"):
    shutil.copytree(get_profile(name).path, tmp_path / name)
    return dataclasses.replace(get_profile(name), path=tmp_path / name)


def test_the_base_tag_hashes_its_build_contexts_and_release(tmp_path):
    profile = _copy(tmp_path)
    tag = base_image(profile)
    assert tag.startswith(f"{profile.image}-") and tag == base_image(get_profile("pi"))
    assert base_image(dataclasses.replace(profile, version="9.9.9")) != tag
    profile.dockerfile.write_text(profile.dockerfile.read_text() + "# changed\n")
    assert base_image(profile) != tag
    assert effective_image(profile, ["jq"]).startswith(f"{base_image(profile)}-")


def test_a_changed_base_is_built_not_reused(tmp_path, monkeypatch):
    profile = _copy(tmp_path)
    old = base_image(profile)
    profile.dockerfile.write_text(profile.dockerfile.read_text() + "# changed\n")
    built: list[list[str]] = []
    monkeypatch.setattr(session, "_image_exists", lambda provider, tag: tag == old)
    monkeypatch.setattr(session.subprocess, "run", lambda cmd, **kw: built.append(cmd))
    tag = session.build_harness("docker", profile)
    assert tag == base_image(profile) != old
    [cmd] = built
    assert cmd[cmd.index("-t") + 1] == tag
    assert f"HARNESS_VERSION={profile.version}" in cmd
