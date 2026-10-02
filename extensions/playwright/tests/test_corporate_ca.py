"""`playwright: {ca: …}`: a private CA the browser sidecar trusts in addition to
the public roots — staged into its state, bound read-only, imported into NSS for
Chromium. Never a verification bypass; absent, nothing changes."""

from __future__ import annotations

import pytest
import yaml
from helpers import make_cfg

from glove.extensions import IN_TREE_DIR, ExtensionError, materialize
from glove.plan import build_session_plan
from glove.runtimes.docker import DockerRuntime

PW = IN_TREE_DIR / "playwright"
PEM = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"
KEY = "-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----\n"
BOUND = "/etc/glove/playwright/corporate-ca.pem"
BYPASS = ("--ignore-certificate-errors", "ignoreHTTPSErrors", "NODE_TLS_REJECT_UNAUTHORIZED",
          "--ignore-https-errors", "--disable-web-security")


def _plan(tmp_path, **settings):
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness="pi", name="s", workdir=str(work), subnet="172.31.4.0/24",
                   extensions={"direct": {}, "playwright": settings})
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "ext"),
                              session_dir=str(tmp_path))


def _pw(tmp_path, plan) -> tuple[dict, str]:
    text = DockerRuntime().render(plan, tmp_path).compose_yaml
    return yaml.safe_load(text)["services"]["glove-s-pw"], text


def test_unset_renders_no_ca(tmp_path):
    plan = _plan(tmp_path)
    materialize(plan.composition)
    pw, _ = _pw(tmp_path, plan)
    assert "NODE_EXTRA_CA_CERTS" not in pw["environment"]
    assert BOUND not in {v["target"] for v in pw["volumes"]}
    assert not (tmp_path / "ext" / "playwright" / "corporate-ca.pem").exists()


@pytest.mark.parametrize("mode", ["headless", "novnc"])
def test_set_stages_binds_read_only_and_trusts(tmp_path, mode):
    (tmp_path / "local").mkdir()
    (tmp_path / "local" / "ca.pem").write_text(PEM)
    plan = _plan(tmp_path, mode=mode, ca="local/ca.pem")
    materialize(plan.composition)
    staged = tmp_path / "ext" / "playwright" / "corporate-ca.pem"
    assert staged.read_text() == PEM
    pw, text = _pw(tmp_path, plan)
    binds = {v["target"]: v for v in pw["volumes"]}
    assert binds[BOUND] == {"type": "bind", "source": str(staged), "target": BOUND, "read_only": True}
    assert pw["environment"]["NODE_EXTRA_CA_CERTS"] == BOUND
    assert not any(tok in text for tok in BYPASS)
    # the harness is untouched by the sidecar's setting (set corporate_ca for it)
    assert "NODE_EXTRA_CA_CERTS" not in plan.environment


@pytest.mark.parametrize("make, err", [
    (lambda p: None, "does not exist"),
    (lambda p: p.mkdir(), "not a regular file"),
    (lambda p: p.write_text("nope\n"), "no PEM certificate"),
    (lambda p: p.write_text(PEM + KEY), "private key"),
])
def test_bad_ca_fails_at_plan_time(tmp_path, make, err):
    make(tmp_path / "ca.pem")
    with pytest.raises(ExtensionError, match=err):
        _plan(tmp_path, ca="ca.pem")


def test_never_the_session_file_or_private_state(tmp_path):
    # the same rule as the harness's corporate_ca: no copying .glove/ out
    (tmp_path / ".glove").mkdir()
    (tmp_path / ".glove" / "ca.pem").write_text(PEM)
    with pytest.raises(ExtensionError, match=r"session file or inside \.glove/"):
        _plan(tmp_path, ca=".glove/ca.pem")


def test_host_mode_ignores_ca(tmp_path):
    # no validation, no staging: the host's Chrome has the host's trust store already
    plan = _plan(tmp_path, mode="host", ca="missing.pem", port=18931, cdp_port=19222)
    assert not any("corporate" in str(h.command) for h in plan.composition.host_services)


def test_entrypoint_imports_into_nss_in_both_modes_and_never_bypasses():
    src = (PW / "image" / "glove-pw-start").read_text()
    assert 'certutil -d "sql:$db" -A -n "glove-corporate-ca-$(basename "$f" .pem)" -t "C,," -i "$f"' in src
    assert src.count("    trust_corporate_ca\n") == 2  # headless and novnc
    assert "libnss3-tools" in (PW / "image" / "Dockerfile").read_text()
    for path in (PW / "image" / "glove-pw-start", PW / "compose" / "services.yml.j2", PW / "hooks.py"):
        text = path.read_text()
        assert not any(tok in text for tok in BYPASS), path
