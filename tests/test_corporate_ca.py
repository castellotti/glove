"""`corporate_ca`: an optional private CA the harness trusts in addition to the
public roots. Off by default — absent, nothing renders differently."""

from __future__ import annotations

import pytest
import yaml
from helpers import make_cfg, make_session, render

from glove import sessiondir as sdm
from glove.config import ConfigError, _coerce
from glove.enforcers.nono.policies import GLOVE_READ
from glove.plan import CORPORATE_CA_PATH, build_session_plan

PEM = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"
# Tokens that would disable TLS verification; none may ever be rendered.
BYPASS = ("NODE_TLS_REJECT_UNAUTHORIZED", "--ignore-certificate-errors", "ignoreHTTPSErrors",
          "PYTHONHTTPSVERIFY", "GIT_SSL_NO_VERIFY", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE")


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
    assert plan.corporate_ca_host_path is None
    assert "NODE_EXTRA_CA_CERTS" not in plan.environment
    assert "corporate" not in text and CORPORATE_CA_PATH not in text


def test_set_resolves_relative_to_the_session_dir_and_binds_read_only(tmp_path):
    (tmp_path / "local").mkdir()
    (tmp_path / "local" / "ca.pem").write_text(PEM)
    plan = _plan(tmp_path, corporate_ca="local/ca.pem")
    assert plan.corporate_ca_host_path == str((tmp_path / "local" / "ca.pem").resolve())
    assert plan.environment["NODE_EXTRA_CA_CERTS"] == CORPORATE_CA_PATH
    from pathlib import Path

    from glove.runtimes.docker import DockerRuntime

    text = DockerRuntime().render(plan, Path(tmp_path)).compose_yaml
    harness = _harness(yaml.safe_load(text))
    binds = [v for v in harness["volumes"] if v.get("target") == CORPORATE_CA_PATH]
    assert binds == [{"type": "bind", "source": plan.corporate_ca_host_path,
                      "target": CORPORATE_CA_PATH, "read_only": True}]
    assert harness["environment"]["NODE_EXTRA_CA_CERTS"] == CORPORATE_CA_PATH
    # trust is only added: no verification-disabling or root-replacing var
    assert not any(tok in text for tok in BYPASS)


def test_an_explicit_env_entry_wins(tmp_path):
    (tmp_path / "ca.pem").write_text(PEM)
    plan = _plan(tmp_path, corporate_ca="ca.pem", env={"NODE_EXTRA_CA_CERTS": "/work/mine.pem"})
    assert plan.environment["NODE_EXTRA_CA_CERTS"] == "/work/mine.pem"


@pytest.mark.parametrize("make, err", [
    (lambda p: None, "does not exist"),
    (lambda p: p.mkdir(), "not a regular file"),
    (lambda p: p.write_text("not a certificate\n"), "no PEM certificate"),
])
def test_bad_inputs_fail_at_plan_time(tmp_path, make, err):
    make(tmp_path / "ca.pem")
    with pytest.raises(ConfigError, match=err):
        _plan(tmp_path, corporate_ca="ca.pem")


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
    assert plan.corporate_ca_host_path == str((tmp_path / "ca.pem").resolve())


def test_the_bind_is_readable_under_every_enforcer_without_a_policy_change(tmp_path):
    # nono grants /etc/glove read in both the harness and tool profiles; srt's
    # tool profile leaves the rootfs readable and hides only the harness home.
    assert any(CORPORATE_CA_PATH.startswith(root + "/") for root in GLOVE_READ)
    (tmp_path / "ca.pem").write_text(PEM)
    for enforcer in ("nono", "nono+srt", "srt"):
        plan = _plan(tmp_path, corporate_ca="ca.pem", enforcer=enforcer)
        assert plan.corporate_ca_host_path
        policies = "".join(plan.policies.values())
        assert CORPORATE_CA_PATH not in policies  # nothing to grant or deny: covered as-is
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
