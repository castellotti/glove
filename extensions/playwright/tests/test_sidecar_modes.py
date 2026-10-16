"""`playwright` sidecar modes (headless, novnc): the browser sidecar's topology,
hardening and settings — the handoff's invariants 1-5 on the rendered project."""

from __future__ import annotations

import json
import re

import pytest
import yaml
from helpers import make_cfg, render

from glove.extensions import IN_TREE_DIR, ExtensionError, materialize
from glove.plan import build_session_plan

PW = IN_TREE_DIR / "playwright"
IMAGE = PW / "image"


def _cfg(tmp_path, egress=("direct", {}), harness="pi", extra=None, **settings):
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    exts = {**({egress[0]: egress[1]} if egress else {}), "playwright": settings, **(extra or {})}
    return make_cfg(harness=harness, name="s", workdir=str(work), extensions=exts, subnet="172.31.4.0/24")


def _plan(tmp_path, **kw):
    return build_session_plan(_cfg(tmp_path, **kw), home_dir=str(tmp_path / "h"),
                              state_dir=str(tmp_path / "ext"))


def _project(tmp_path, **kw) -> dict:
    return yaml.safe_load(render(_cfg(tmp_path, **kw), tmp_path)[1])


def test_needs_an_egress_provider(tmp_path):
    with pytest.raises(ExtensionError, match="requires the 'egress' slot"):
        _plan(tmp_path, egress=None)


def test_headless_sidecar_is_hardened_and_alone_on_its_network(tmp_path):
    doc = _project(tmp_path)
    svcs, nets = doc["services"], doc["networks"]
    pw = svcs["glove-s-pw"]
    # invariant 3: only on browser-net, which is internal
    assert list(pw["networks"]) == ["glove-s-browser-net"] and nets["glove-s-browser-net"]["internal"] is True
    assert pw["command"] == ["glove-pw-start", "headless"] and pw["init"] is True
    assert pw["user"] == "501:20" and pw["cap_drop"] == ["ALL"] and pw["read_only"] is True
    assert pw["ipc"] == "private" and pw["shm_size"] == "256m"
    assert (pw["pids_limit"], pw["mem_limit"], pw["cpus"]) == (2048, "2g", 2.0)
    # invariant 2: the userns profile, sandbox on by default
    assert any(o.endswith("seccomp/chromium-userns.json") for o in pw["security_opt"])
    assert pw["environment"]["PW_SANDBOX"] == "on" and pw["environment"]["PW_PROFILE"] == "ephemeral"
    assert pw["environment"]["PW_ALLOWED_HOST"] == "glove-s-browser:8931"
    assert pw["environment"]["PW_PROXY"] == "http://glove-s-browser-egress:8888"
    assert pw["healthcheck"]["test"][-1] == "exec 3<>/dev/tcp/127.0.0.1/8931"
    # its binds: the output dir, the download staging dir and the MCP config, all in its own state
    binds = {v["target"]: v for v in pw["volumes"]}
    policy = "/etc/opt/chrome_for_testing/policies/managed/glove.json"
    assert set(binds) == {"/data/output", "/data/staging", "/etc/glove/playwright/mcp.json", policy}
    assert binds["/etc/glove/playwright/mcp.json"]["read_only"] is True
    assert binds[policy]["read_only"] is True
    assert all(v["source"].startswith(str(tmp_path / "ext" / "playwright")) for v in binds.values())
    # invariant 1: nothing published, anywhere
    assert not any("ports" in s for s in svcs.values())
    # the two forwarders: the harness's way in, the sidecar's way out
    browser, egress = svcs["glove-s-browser"], svcs["glove-s-browser-egress"]
    assert set(browser["networks"]) == {"glove-s-net", "glove-s-browser-net"}
    assert set(egress["networks"]) == {"glove-s-browser-net", "glove-s-egress"}  # never the harness net
    # invariant 4: the harness never joins browser-net
    harness = next(s for n, s in svcs.items() if "glove-s-net" in s["networks"] and n not in (
        "glove-s-browser", "glove-s-llm", "glove-s-browser-egress"))
    assert list(harness["networks"]) == ["glove-s-net"]


def test_sandbox_off_uses_the_default_profile(tmp_path):
    pw = _project(tmp_path, chromium_sandbox="off")["services"]["glove-s-pw"]
    assert any(o.endswith("seccomp/default.json") for o in pw["security_opt"])
    assert pw["environment"]["PW_SANDBOX"] == "off"


def test_the_mcp_never_gets_a_cdp_port_or_file_access():
    # invariant 5: fixed server-side, in the entrypoint
    src = (IMAGE / "glove-pw-start").read_text()
    for flag in ("--cdp-endpoint", "--remote-debugging-port", "--allow-unrestricted-file-access"):
        assert flag not in src
    assert "--proxy-server \"$PW_PROXY\"" in src and "--allowed-hosts \"$PW_ALLOWED_HOST\"" in src
    # with the sandbox on, both modes prove it before serving (fail closed at `glove up`)
    assert "prepare() {\n  require_sandbox\n" in src and src.count("    prepare\n") == 2
    assert 'chromium_sandbox: "off"' in src
    # every MCP client shares one context: a restarted harness's new session reuses the browser
    assert "args+=(--shared-browser-context)" in src


def test_one_playwright_pin():
    pkg = json.loads((IMAGE / "package.json").read_text())
    lock = json.loads((IMAGE / "package-lock.json").read_text())
    version = pkg["dependencies"]["playwright-core"]
    assert lock["packages"]["node_modules/playwright-core"]["version"] == version
    assert f"FROM mcr.microsoft.com/playwright:v{version}-noble@sha256:" in (IMAGE / "Dockerfile").read_text()
    assert "npx" not in (IMAGE / "Dockerfile").read_text().replace("No runtime `npx -y`", "")
    # all_tools was listed for this version: re-list it when the pin moves
    stamp = re.search(r"playwright-core (\S+), as in", (IMAGE.parent / "extension.yml").read_text())
    assert stamp and stamp.group(1) == version


def test_mcp_config_and_dirs(tmp_path):
    plan = _plan(tmp_path, timezone="Europe/Berlin", locale="de-DE")
    materialize(plan.composition)
    state = tmp_path / "ext" / "playwright"
    cfg = json.loads((state / "mcp.json").read_text())
    assert cfg["browser"]["contextOptions"] == {"timezoneId": "Europe/Berlin", "locale": "de-DE"}
    assert cfg["browser"]["launchOptions"]["args"] == ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
    assert (state / "output").is_dir() and not (state / "profile").exists()


def test_novnc_mode(tmp_path):
    doc = _project(tmp_path, mode="novnc", clipboard="to-browser")
    pw = doc["services"]["glove-s-pw"]
    assert pw["command"] == ["glove-pw-start", "novnc"]
    assert pw["environment"]["VNC_ACCEPT_INPUT"] == "false" and pw["environment"]["VNC_CLIPBOARD"] == "to-browser"
    # the VNC passwords never leave the sidecar: no compose secret, no env, no file
    assert "secrets" not in pw and not doc.get("secrets")
    assert not any("PASS" in k for k in pw["environment"])
    assert not any("ports" in s for s in doc["services"].values())
    plan = _plan(tmp_path / "p", mode="novnc", viewport="1600x900")
    materialize(plan.composition)
    args = json.loads((tmp_path / "p" / "ext" / "playwright" / "mcp.json").read_text())["browser"]["launchOptions"]
    assert "--window-size=1600,900" in args["args"]
    assert "operator may be watching" in dict(plan.composition.rendered_briefs())["playwright"]


def test_novnc_passwords_are_generated_in_the_sidecar():
    src = (IMAGE / "glove-pw-start").read_text()
    assert "randomBytes(6)" in src and "umask 077" in src and "/tmp/vnc/full" in src and "/tmp/vnc/view" in src
    assert "-SecurityTypes VncAuth -PasswordFile /tmp/vnc/passwd" in src and "-localhost" in src
    assert "websockify --web /usr/share/novnc 127.0.0.1:6080 127.0.0.1:5900" in src


def test_allow_control_is_novnc_only(tmp_path):
    with pytest.raises(ExtensionError, match="allow_control applies to mode: novnc only"):
        _plan(tmp_path, allow_control=True)
    pw = _project(tmp_path / "n", mode="novnc", allow_control=True)["services"]["glove-s-pw"]
    assert pw["environment"]["VNC_ACCEPT_INPUT"] == "true"


def test_session_profile_persists_in_state_and_is_refused_under_tor(tmp_path):
    pw = _project(tmp_path, profile="session")["services"]["glove-s-pw"]
    prof = next(v for v in pw["volumes"] if v["target"] == "/data/profile")
    assert prof["source"] == str(tmp_path / "ext" / "playwright" / "profile") and not prof.get("read_only")
    with pytest.raises(ExtensionError, match="links your Tor sessions"):
        _plan(tmp_path / "t", egress=("tor", {}), profile="session")
    _plan(tmp_path / "t2", egress=("tor", {}), profile="session", allow_persistent_profile_with_tor=True)


def test_downloads_and_uploads_are_opt_in_and_never_a_work_bind(tmp_path):
    # downloads: an output (<session>/browser-output, the sidecar writes it, the
    # harness reads it at /work/browser-output); uploads: an input
    # (<session>/browser-uploads, the harness writes it at /work/browser-uploads,
    # the sidecar reads it at the same path). Neither binds a path in /work.
    plan, text = render(_cfg(tmp_path, downloads="work", uploads="work"), tmp_path, session_dir=str(tmp_path))
    doc = yaml.safe_load(text)
    pw, harness = doc["services"]["glove-s-pw"], doc["services"][plan.harness_service]
    binds = {v["target"]: v for v in pw["volumes"]}
    out, up = binds["/run/glove-output/browser-output"], binds["/work/browser-uploads"]
    assert out["source"] == str(tmp_path / "browser-output") and not out.get("read_only")
    assert up["source"] == str(tmp_path / "browser-uploads") and up["read_only"] is True
    work = str(tmp_path / "work")
    assert "/data/output" not in binds and not any(work in str(v.get("source")) for v in binds.values())
    assert pw["environment"]["PW_OUTPUT"] == "/run/glove-output/browser-output"
    assert pw["environment"]["PW_UPLOADS"] == "/work/browser-uploads"
    hb = {v["target"]: v for v in harness["volumes"]}
    assert hb["/work/browser-output"]["read_only"] and not hb["/work/browser-uploads"].get("read_only")
    materialize(plan.composition)
    assert (tmp_path / "browser-output").is_dir() and (tmp_path / "browser-uploads").is_dir()
    brief = dict(plan.composition.rendered_briefs())["playwright"]
    assert "/work/browser-output/" in brief and "/work/browser-uploads/" in brief
    assert "operator may be watching" not in brief  # novnc only
    # off by default: the state output dir, the image's empty uploads dir
    pw = _project(tmp_path / "off")["services"]["glove-s-pw"]
    assert "PW_OUTPUT" not in pw["environment"] and "PW_UPLOADS" not in pw["environment"]


def test_an_upload_dir_planted_as_a_link_is_refused(tmp_path):
    # the input's mount point is in /work, which the agent writes
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "browser-uploads").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(Exception, match="browser-uploads"):
        render(_cfg(tmp_path, uploads="work"), tmp_path, session_dir=str(tmp_path))


def test_downloads_stage_on_disk_not_in_tmpfs(tmp_path):
    plan = _plan(tmp_path)
    materialize(plan.composition)
    state = tmp_path / "ext" / "playwright"
    cfg = json.loads((state / "mcp.json").read_text())
    assert cfg["browser"]["launchOptions"]["downloadsPath"] == "/data/staging"
    (state / "downloading" / "staged").write_text("x")
    materialize(plan.composition)  # never emptied here: a running sidecar may be using it
    assert (state / "downloading" / "staged").exists()
    # the sidecar clears it as it starts (prepare, in both modes), before the browser
    assert "  find /data/staging -mindepth 1 -delete" in (IMAGE / "glove-pw-start").read_text()


@pytest.mark.parametrize("sub", ["", "browser-output"])
def test_a_sidecar_never_binds_work_or_a_path_in_it(tmp_path, monkeypatch, sub):
    import glove.compose as compose_mod

    real = compose_mod._volumes

    def widen(comp, a, short, vols, *rest, **kw):
        if a.name == "playwright":
            vols = [*vols, {"type": "bind", "source": str(comp.work_dir / sub), "target": "/w"}]
        return real(comp, a, short, vols, *rest, **kw)

    monkeypatch.setattr(compose_mod, "_volumes", widen)
    with pytest.raises(ExtensionError, match="never binds a path in /work"):
        render(_cfg(tmp_path), tmp_path)


def test_vibe_gets_the_allowlist_in_sidecar_modes(tmp_path):
    plan = _plan(tmp_path, harness="vibe", tools=["browser_navigate", "browser_snapshot"])
    pw = next(s for _, s in plan.composition.mcp if s["name"] == "playwright")
    assert pw["tools"] == ["browser_navigate", "browser_snapshot"]


def test_bad_settings(tmp_path):
    for bad, match in (({"viewport": "big"}, "must match"), ({"timezone": "UTC; rm"}, "must match"),
                       ({"tools": ["browser_navigate", "evil tool"]}, "must match"),
                       ({"mode": "vm"}, "must be one of")):
        with pytest.raises(ExtensionError, match=match):
            _plan(tmp_path, **bad)


def test_observe_gates_both_hops(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    svcs = _project(tmp_path, extra={"observe": {}})["services"]
    browser, egress = svcs["glove-s-browser"]["command"], svcs["glove-s-browser-egress"]["command"]
    assert "--tool" in browser and "browser" in browser
    joined = " ".join(map(str, egress))
    assert "--client playwright" in joined and "chain:http://glove-s-direct-proxy:8888" in joined


def test_host_mode_builds_no_sidecar_image(tmp_path, monkeypatch):
    import glove.session as session_mod

    built = []
    monkeypatch.setattr(session_mod, "_image_exists", lambda *a: False)
    monkeypatch.setattr(session_mod.subprocess, "run", lambda cmd, **kw: built.append(cmd))
    session_mod.build_extension_images("docker", _plan(tmp_path, egress=None, mode="host"))
    assert not any("ext-playwright-pw" in " ".join(c) for c in built)
    session_mod.build_extension_images("docker", _plan(tmp_path / "h"))
    assert any("ext-playwright-pw" in " ".join(c) for c in built)


def test_podman_refuses_the_sandbox_profile_it_cannot_apply(tmp_path, monkeypatch):
    import glove.runtimes.podman as podman_mod
    from glove.runtimes.podman import PodmanRuntime

    monkeypatch.setattr(podman_mod, "_host_info", lambda cli: {})
    cfg = _cfg(tmp_path)
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "ext"))
    with pytest.raises(ExtensionError, match=r'cannot apply .*chromium_sandbox: "off"'):
        PodmanRuntime().render(plan, tmp_path)
    cfg = _cfg(tmp_path / "off", chromium_sandbox="off")
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h2"), state_dir=str(tmp_path / "ext2"))
    pw = yaml.safe_load(PodmanRuntime().render(plan, tmp_path / "off").compose_yaml)["services"]["glove-s-pw"]
    assert not any("seccomp" in o for o in pw["security_opt"])  # podman's built-in default applies
