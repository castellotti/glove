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
    out = _expand("x --allowed-hosts glove-{session}-browser:8931 --in {workdir} --h {home}", cfg, "vibe-local")
    assert "glove-vibe-local-browser:8931" in out
    assert f"--in {os.path.realpath(work)}" in out
    assert out.endswith(os.path.expanduser("~"))


def test_retired_placeholders_are_not_expanded(tmp_path):
    # media_dir/chrome_profile moved into the playwright extension's own state
    # (per session); core no longer knows browser paths.
    cfg, _ = _cfg(tmp_path)
    assert _expand("{media_dir} {chrome_profile}", cfg, "s", tmp_path) == "{media_dir} {chrome_profile}"


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
