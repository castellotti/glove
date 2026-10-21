"""`playwright: {ca: …}`: a private CA the browser sidecar trusts in addition to
the public roots and corporate_ca — a core `type: ca` setting (glove/cafile.py),
imported into NSS for Chromium. Never a verification bypass; absent, nothing
changes."""

from __future__ import annotations

import pytest
from helpers import PEM, plan_pw, pw_service

from glove.cafile import TRUST_DIR, TRUST_ENV
from glove.config import ConfigError
from glove.extensions import IN_TREE_DIR

PW = IN_TREE_DIR / "playwright"
KEY = "-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----\n"
BYPASS = ("--ignore-certificate-errors", "ignoreHTTPSErrors", "NODE_TLS_REJECT_UNAUTHORIZED",
          "--ignore-https-errors", "--disable-web-security")


_plan, _pw = plan_pw, pw_service


def test_unset_renders_no_ca(tmp_path):
    plan = _plan(tmp_path)
    pw, _ = _pw(tmp_path, plan)
    assert not set(TRUST_ENV) & set(pw["environment"]) and pw["command"][0] == "glove-pw-start"
    assert TRUST_DIR not in {v["target"] for v in pw["volumes"]}


@pytest.mark.parametrize("mode", ["headless", "novnc"])
def test_set_is_copied_by_core_and_trusted_with_corporate_ca(tmp_path, mode):
    (tmp_path / "local").mkdir()
    (tmp_path / "local" / "ca.pem").write_text(PEM)
    (tmp_path / "corp.pem").write_text(PEM)
    plan = _plan(tmp_path, mode=mode, ca="local/ca.pem", corporate_ca="corp.pem")
    assert plan.composition.trust["playwright.ca.pem"] == (tmp_path / "local" / "ca.pem").resolve()
    pw, text = _pw(tmp_path, plan)
    binds = {v["target"]: v for v in pw["volumes"]}
    assert binds[TRUST_DIR] == {"type": "bind", "source": plan.trust_host_dir, "target": TRUST_DIR, "read_only": True}
    # Node (the MCP) reads them from NODE_EXTRA_CA_CERTS, and glove-pw-start imports them into NSS
    assert pw["environment"]["NODE_EXTRA_CA_CERTS"] == TRUST_ENV["NODE_EXTRA_CA_CERTS"]
    assert f"{TRUST_DIR}/corporate_ca.pem {TRUST_DIR}/playwright.ca.pem" in pw["entrypoint"][2]
    assert pw["entrypoint"][3:] == ["glove-trust"] and pw["command"] == ["glove-pw-start", mode]
    assert not any(tok in text for tok in BYPASS)
    # the harness trusts corporate_ca, never the sidecar's own CA
    assert plan.trusted_cas == [f"{TRUST_DIR}/corporate_ca.pem"]


@pytest.mark.parametrize("make, err", [
    (lambda p: None, "does not exist"),
    (lambda p: p.mkdir(), "not a regular file"),
    (lambda p: p.write_text("nope\n"), "no PEM certificate"),
    (lambda p: p.write_text(PEM + KEY), "private key"),
])
def test_bad_ca_fails_at_plan_time(tmp_path, make, err):
    make(tmp_path / "ca.pem")
    with pytest.raises(ConfigError, match=err):
        _plan(tmp_path, ca="ca.pem")


def test_never_the_session_file_or_private_state(tmp_path):
    # the same rule as the harness's corporate_ca: no copying .glove/ out
    (tmp_path / ".glove").mkdir()
    (tmp_path / ".glove" / "ca.pem").write_text(PEM)
    with pytest.raises(ConfigError, match=r"session file or inside \.glove/"):
        _plan(tmp_path, ca=".glove/ca.pem")


def test_entrypoint_imports_into_nss_in_both_modes_and_never_bypasses():
    src = (PW / "image" / "glove-pw-start").read_text()
    assert 'certutil -d "sql:$db" -A -n "glove-ca-$(basename "$f" .pem)" -t "C,," -i "$f"' in src
    assert 'local ca="${NODE_EXTRA_CA_CERTS:-}"' in src
    assert "\n  trust_session_cas\n" in src.split("prepare() {")[1].split("}")[0]
    assert src.count("    prepare\n") == 2  # headless and novnc
    assert "libnss3-tools" in (PW / "image" / "Dockerfile").read_text()
    for path in (PW / "image" / "glove-pw-start", PW / "compose" / "services.yml.j2", PW / "hooks.py"):
        text = path.read_text()
        assert not any(tok in text for tok in BYPASS), path
