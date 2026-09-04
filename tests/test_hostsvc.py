"""Host-service placeholder expansion + config round-trip."""

from __future__ import annotations

import os

from glove.config import Config, HostService, resolve
from glove.hostsvc import _expand


def _cfg(tmp_path):
    work = tmp_path / "project"
    work.mkdir()
    cfg = Config(harness="vibe", workdir=str(work), name="vibe-local")
    return cfg, work


def test_expand_placeholders(tmp_path):
    cfg, work = _cfg(tmp_path)
    sdir = tmp_path / "state"
    cmd = "mcp --allowed-hosts glove-{session}-browser:8931 --output-dir {media_dir}"
    out = _expand(cmd, cfg, "vibe-local", sdir)
    assert "glove-vibe-local-browser:8931" in out
    assert out.endswith(os.path.join(str(sdir), "media"))


def test_media_dir_never_inside_project(tmp_path):
    # glove must not litter the project working tree — the browser output dir
    # lives in glove's own session state, never under the workdir.
    cfg, work = _cfg(tmp_path)
    sdir = tmp_path / "state"
    out = _expand("{media_dir}", cfg, "vibe-local", sdir)
    assert str(os.path.realpath(work)) not in out
    assert "research" not in out
    # bare expansion (no session dir) still avoids the project — falls back to ~/.glove
    bare = _expand("{media_dir}", cfg, "vibe-local")
    assert str(os.path.realpath(work)) not in bare
    assert bare.startswith(os.path.join(os.path.expanduser("~"), ".glove"))


def test_expand_chrome_profile_and_home(tmp_path):
    cfg, _ = _cfg(tmp_path)
    out = _expand("chrome --user-data-dir={chrome_profile}", cfg, "vibe-local")
    assert out.endswith(os.path.join(os.path.expanduser("~"), ".glove", "chrome-profile"))


def test_host_services_coerced_from_file(tmp_path):
    (tmp_path / "glove.yaml").write_text(
        "harness: vibe\n"
        "host_services:\n"
        "  - name: model-tunnel\n"
        "    command: ssh -N -L 127.0.0.1:8899:127.0.0.1:8080 llm-host.example\n"
        "    ready_port: 8899\n"
        "  - name: chrome\n"
        "    command: chrome --foo\n"
        "    ready_port: 9222\n"
        "    keep: true\n"
    )
    cfg = resolve(env_config_path=tmp_path / "glove.yaml", overrides={})
    assert [s.name for s in cfg.host_services] == ["model-tunnel", "chrome"]
    assert cfg.host_services[0].ready_port == 8899
    assert cfg.host_services[1].keep is True


def test_host_services_round_trip():
    cfg = Config(harness="vibe", name="s")
    cfg.host_services = [HostService(name="t", command="sleep 1", ready_port=1234)]
    import yaml

    data = yaml.safe_load(cfg.to_yaml())
    assert data["host_services"][0]["name"] == "t"
    assert data["host_services"][0]["ready_port"] == 1234
