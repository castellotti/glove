"""`corporate_ca`: an optional private CA the harness trusts in addition to the
public roots, and glove/cafile.py's one way to trust a CA. Off by default —
absent, nothing renders differently."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml
from helpers import PEM, make_cfg, make_session, render

from glove import cafile
from glove import sessiondir as sdm
from glove.cafile import CA_DIR, CORPORATE_CA, TRUST_DIR, TRUST_ENV
from glove.config import ConfigError, _coerce
from glove.enforcers.base import write_roots
from glove.enforcers.nono.policies import GLOVE_READ
from glove.plan import build_session_plan

KEYS = [f"-----BEGIN {kind}PRIVATE KEY-----\nMIIEfake\n-----END {kind}PRIVATE KEY-----\n"
        for kind in ("", "RSA ", "EC ", "ENCRYPTED ", "OPENSSH ")]
# Tokens that would disable TLS verification; none may ever be rendered.
BYPASS = ("NODE_TLS_REJECT_UNAUTHORIZED", "--ignore-certificate-errors", "ignoreHTTPSErrors",
          "PYTHONHTTPSVERIFY", "GIT_SSL_NO_VERIFY", "http.sslVerify")


def _cfg(tmp_path, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return make_cfg(harness="pi", workdir=str(work), name="s", **kw)


def _plan(tmp_path, **kw):
    return build_session_plan(_cfg(tmp_path, **kw), home_dir=str(tmp_path / "h"),
                              state_dir=str(tmp_path / "ext"), session_dir=str(tmp_path))


def _harness(doc: dict) -> dict:
    return doc["services"]["glove-s-harness"]


def test_config_key_defaults_unset_and_round_trips():
    assert _coerce({}).corporate_ca is None
    cfg = _coerce({"corporate_ca": "local/ca.pem"})
    assert _coerce(yaml.safe_load(cfg.to_yaml())).corporate_ca == "local/ca.pem"
    with pytest.raises(ConfigError, match="unknown config keys"):
        _coerce({"corporate_ca": "x", "corporate_cert": "y"})


def test_session_file_accepts_the_key_and_still_refuses_bogus_ones(tmp_path):
    d = make_session(tmp_path / "a", "corporate_ca: local/ca.pem\n")
    sd = sdm.SessionDir(d)
    assert sdm.to_config(sd, sdm.load_file(sd), "a-000000").corporate_ca == "local/ca.pem"
    d = make_session(tmp_path / "b", "corporate_ca: x\ncorporate_cert: y\n")
    with pytest.raises(sdm.SessionError, match="unknown key"):
        sdm.load_file(sdm.SessionDir(d))


def test_unset_leaves_plan_and_render_untouched(tmp_path):
    plan, text = render(_cfg(tmp_path), tmp_path)
    assert plan.trust_host_dir is None and plan.trusted_cas == []
    assert not set(TRUST_ENV) & set(plan.environment)
    assert "corporate" not in text and TRUST_DIR not in text and CA_DIR not in text and "glove-trust" not in text
    assert plan.derived_dockerfile is None  # pi alone: the base image


def test_set_copies_the_ca_and_builds_the_bundle_before_the_enforcer(tmp_path):
    (tmp_path / "local").mkdir()
    (tmp_path / "local" / "ca.pem").write_text(PEM)
    plan = _plan(tmp_path, corporate_ca="local/ca.pem")
    assert plan.composition.trust == {CORPORATE_CA: (tmp_path / "local" / "ca.pem").resolve()}
    assert plan.trust_host_dir == str(tmp_path / "trust")  # beside the home, in .glove/
    assert plan.trusted_cas == [f"{TRUST_DIR}/{CORPORATE_CA}"]
    # the enforcer's own command, run once the bundle is built
    assert plan.command[:2] == ["/bin/sh", "-c"] and plan.command[3:] == ["glove-trust", *_plan(tmp_path).command]
    assert CA_DIR in plan.hardening.tmpfs
    assert {k: plan.environment[k] for k in TRUST_ENV} == TRUST_ENV
    assert plan.derived_dockerfile is None  # nothing baked: a new CA rebuilds no image

    from glove.runtimes.docker import DockerRuntime

    text = DockerRuntime().render(plan, Path(tmp_path)).compose_yaml
    harness = _harness(yaml.safe_load(text))
    assert [v for v in harness["volumes"] if v.get("target") == TRUST_DIR] == [
        {"type": "bind", "source": plan.trust_host_dir, "target": TRUST_DIR, "read_only": True}]
    assert {"type": "tmpfs", "target": CA_DIR, "tmpfs": {"mode": 0o1777}} in harness["volumes"]
    # trust is only added: no verification-disabling var
    assert not any(tok in text for tok in BYPASS)


def test_an_explicit_env_entry_wins(tmp_path):
    (tmp_path / "ca.pem").write_text(PEM)
    plan = _plan(tmp_path, corporate_ca="ca.pem",
                 env={"SSL_CERT_FILE": "/work/mine.pem", "NODE_EXTRA_CA_CERTS": "/work/node.pem"})
    assert plan.environment["SSL_CERT_FILE"] == "/work/mine.pem"
    assert plan.environment["NODE_EXTRA_CA_CERTS"] == "/work/node.pem"
    assert plan.environment["GIT_SSL_CAINFO"] == f"{CA_DIR}/bundle.pem"


def _sh(script: str, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/sh", "-c", script, "glove-trust", *argv], capture_output=True, text=True,
                          check=False)


def test_the_bundle_is_the_roots_then_every_ca(tmp_path, monkeypatch):
    roots, a, b = tmp_path / "roots.pem", tmp_path / "a.pem", tmp_path / "b.pem"
    roots.write_text(PEM.replace("fake", "roots"))
    a.write_text(PEM.replace("fake", "a").rstrip("\n"))  # no trailing newline: the next CA still parses
    b.write_text(PEM.replace("fake", "b"))
    monkeypatch.setattr(cafile, "SYSTEM_ROOTS", str(roots))
    r = _sh(cafile.trust_script([str(a), str(b)], dest=str(tmp_path)) + 'exec "$@"', "echo", "started")
    assert (r.returncode, r.stdout) == (0, "started\n"), r.stderr
    extra, bundle = (tmp_path / "extra.pem").read_text(), (tmp_path / "bundle.pem").read_text()
    assert [x for x in ("roots", "a", "b") if f"MIIB{x}" in extra] == ["a", "b"]
    assert bundle.index("MIIBroots") < bundle.index("MIIBa") < bundle.index("MIIBb")
    assert "-----END CERTIFICATE-----\n" in extra.split("MIIBb")[0]


def test_only_a_channels_ca_is_waited_for(tmp_path, monkeypatch):
    # a copy in TRUST_DIR is there from the start or never: no 30 s wait, no
    # crash-looping sidecar polling for it
    import time

    roots = tmp_path / "roots.pem"
    roots.write_text(PEM)
    monkeypatch.setattr(cafile, "SYSTEM_ROOTS", str(roots))
    monkeypatch.setattr(cafile, "TRUST_DIR", str(tmp_path / "trust"))
    start = time.monotonic()
    r = _sh(cafile.trust_script([str(tmp_path / "trust" / "corporate_ca.pem")], dest=str(tmp_path)))
    assert r.returncode == 90 and "is missing" in r.stderr and time.monotonic() - start < 5
    assert "sleep" not in cafile.trust_script([str(tmp_path / "trust" / "x.pem")])
    assert "sleep 1" in cafile.trust_script(["/run/glove/llm-ca/ca.pem"])


def test_a_ca_is_checked_again_when_copied_and_must_be_text(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(PEM.encode() + b"# \xff\n")
    with pytest.raises(ConfigError, match="as text"):
        _plan(tmp_path, corporate_ca="ca.pem")
    ca.write_text(PEM)
    plan = _plan(tmp_path, corporate_ca="ca.pem")
    ca.write_text(PEM + KEYS[0])  # changed after the plan: never copied
    with pytest.raises(ConfigError, match="private key"):
        cafile.read_ca("corporate_ca", plan.composition.trust[CORPORATE_CA])


def test_a_sidecars_own_ca_is_never_bound_into_the_harness(tmp_path):
    (tmp_path / "ca.pem").write_text(PEM)
    work = tmp_path / "work"
    work.mkdir()
    cfg = make_cfg(harness="pi", workdir=str(work), name="s",
                   extensions={"direct": {}, "playwright": {"ca": "ca.pem"}})
    plan, text = render(cfg, tmp_path, session_dir=str(tmp_path))
    assert plan.trust_host_dir and not plan.trusts_copies and plan.trusted_cas == []
    assert TRUST_DIR not in str(_harness(yaml.safe_load(text)).get("volumes"))


@pytest.mark.parametrize("missing", ["ca", "roots"])
def test_a_missing_ca_or_no_roots_refuses_to_start(tmp_path, monkeypatch, missing):
    roots, ca = tmp_path / "roots.pem", tmp_path / "ca.pem"
    (ca if missing == "roots" else roots).write_text(PEM)
    monkeypatch.setattr(cafile, "SYSTEM_ROOTS", str(roots))
    monkeypatch.setattr(cafile, "CA_WAIT", 0)
    r = _sh(cafile.trust_script([str(ca)], dest=str(tmp_path)) + 'exec "$@"', "echo", "started")
    assert r.returncode == 90 and "started" not in r.stdout
    assert ("is missing" if missing == "ca" else "no CA roots") in r.stderr
    assert not (tmp_path / "bundle.pem").exists()


@pytest.mark.parametrize("make, err", [
    (lambda p: None, "does not exist"),
    (lambda p: p.mkdir(), "not a regular file"),
    (lambda p: p.write_text("not a certificate\n"), "no PEM certificate"),
])
def test_bad_inputs_fail_at_plan_time(tmp_path, make, err):
    make(tmp_path / "ca.pem")
    with pytest.raises(ConfigError, match=err):
        _plan(tmp_path, corporate_ca="ca.pem")


@pytest.mark.parametrize("key", KEYS)
def test_a_bundle_with_a_private_key_is_refused(tmp_path, key):
    # a combined cert+key PEM would hand the key to the agent
    (tmp_path / "ca.pem").write_text(PEM + key)
    with pytest.raises(ConfigError, match="private key"):
        _plan(tmp_path, corporate_ca="ca.pem")


@pytest.mark.parametrize("value", [True, 123, ["ca.pem"], {"path": "ca.pem"}])
def test_a_non_string_value_is_a_config_error(tmp_path, value):
    with pytest.raises(ConfigError, match="must be a path string"):
        _plan(tmp_path, corporate_ca=value)


def test_never_the_session_file_or_private_state(tmp_path):
    (tmp_path / "glove-session.yml").write_text(PEM)
    (tmp_path / ".glove").mkdir()
    (tmp_path / ".glove" / "ca.pem").write_text(PEM)
    for value in ("glove-session.yml", ".glove/ca.pem"):
        with pytest.raises(ConfigError, match=r"session file or inside \.glove/"):
            _plan(tmp_path, corporate_ca=value)


def test_relative_path_needs_a_session_dir(tmp_path):
    with pytest.raises(ConfigError, match="absolute path"):
        build_session_plan(_cfg(tmp_path, corporate_ca="ca.pem"), home_dir=str(tmp_path / "h"))


def test_absolute_path_works_without_a_session_dir(tmp_path):
    (tmp_path / "ca.pem").write_text(PEM)
    plan = build_session_plan(_cfg(tmp_path, corporate_ca=str(tmp_path / "ca.pem")), home_dir=str(tmp_path / "h"))
    assert plan.composition.trust == {CORPORATE_CA: (tmp_path / "ca.pem").resolve()}


def test_every_enforcer_lets_the_agent_read_the_cas_and_write_neither(tmp_path):
    # nono grants /etc/glove read in both the harness and tool profiles; srt's
    # tool profile leaves the rootfs readable and hides only the harness home;
    # neither grants a write under /etc/glove, so the bundle is glove's alone.
    assert all(any(d.startswith(root + "/") for root in GLOVE_READ) for d in (TRUST_DIR, CA_DIR))
    (tmp_path / "ca.pem").write_text(PEM)
    for enforcer in ("nono", "nono+srt", "srt"):
        plan = _plan(tmp_path, corporate_ca="ca.pem", enforcer=enforcer)
        assert not any(w == "/" or "/etc/glove".startswith(w.rstrip("/") + "/") or w.startswith("/etc/glove")
                       for w in write_roots(plan))
        policies = "".join(plan.policies.values())
        assert TRUST_DIR not in policies and CA_DIR not in policies  # nothing to grant or deny
        if enforcer == "nono":
            assert "/etc/glove" in policies


def test_check_resolves_relative_extension_paths_when_the_plan_failed(tmp_path):
    # `glove check` re-composes the extensions when the plan fails (e.g. a bad
    # corporate_ca); a valid relative path setting must not be reported too.
    from glove.doctor import extension_checks

    (tmp_path / "ca.pem").write_text(PEM)
    requested = {"llm": make_cfg().extensions["llm"], "direct": {}, "playwright": {"ca": "ca.pem"}}
    assert extension_checks(requested, harness="pi", session_dir=tmp_path)[0].status == "ok"
    assert extension_checks(requested, harness="pi")[0].status == "fail"
