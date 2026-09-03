"""Host-service placeholder expansion + config round-trip (B.2)."""

from __future__ import annotations

import os

from glove.config import Config, HostService, resolve
from glove.hostsvc import _expand


def _cfg(tmp_path):
    work = tmp_path / "leeroy"
    work.mkdir()
    cfg = Config(harness="vibe", workdir=str(work), name="vibe-local")
    return cfg, work


def test_expand_placeholders(tmp_path):
    cfg, work = _cfg(tmp_path)  # harness=vibe → collection defaults to "vibe"
    cmd = "mcp --allowed-hosts glove-{session}-browser:8931 --output-dir {media_dir}"
    out = _expand(cmd, cfg, "vibe-local")
    assert "glove-vibe-local-browser:8931" in out
    assert out.endswith(os.path.join(str(os.path.realpath(work)), "research", "vibe", "media"))


def test_collection_overrides_media_dir(tmp_path):
    cfg, work = _cfg(tmp_path)
    cfg.collection = "pi"
    out = _expand("{media_dir}|{filtered_dir}", cfg, "pi-local")
    base = os.path.join(str(os.path.realpath(work)), "research", "pi")
    assert out == f"{os.path.join(base, 'media')}|{os.path.join(base, 'filtered')}"


def test_expand_chrome_profile_and_home(tmp_path):
    cfg, _ = _cfg(tmp_path)
    out = _expand("chrome --user-data-dir={chrome_profile}", cfg, "vibe-local")
    assert out.endswith(os.path.join(os.path.expanduser("~"), ".glove", "chrome-profile"))


def test_host_services_coerced_from_file(tmp_path):
    (tmp_path / "glove.yaml").write_text(
        "harness: vibe\n"
        "host_services:\n"
        "  - name: model-tunnel\n"
        "    command: ssh -N -L 127.0.0.1:8899:127.0.0.1:8080 faustulus.local\n"
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
