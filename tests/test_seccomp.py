"""Seccomp profile tests: the surgical relaxation, nothing more."""

from __future__ import annotations

import json

from glove.runtimes.seccomp import DEFAULT_PROFILE, NESTED_USERNS_PROFILE
from glove.runtimes.seccomp.make_profile import (
    MUST_STAY_GATED,
    NS_SYSCALLS,
    build_nested,
    is_unconditionally_allowed,
)


def _default():
    return json.loads(DEFAULT_PROFILE.read_text())


def test_default_gates_namespace_and_dangerous_syscalls():
    d = _default()
    # In the vendored default, none of these are unconditionally allowed.
    for s in ("mount", "unshare", "setns", "bpf", "perf_event_open"):
        assert not is_unconditionally_allowed(d, s), s


def test_nested_allows_exactly_the_ns_syscalls():
    nested = build_nested(_default())
    for s in NS_SYSCALLS:
        assert is_unconditionally_allowed(nested, s), f"{s} should be unconditionally allowed"


def test_nested_does_not_leak_dangerous_syscalls():
    nested = build_nested(_default())
    leaked = [s for s in MUST_STAY_GATED if is_unconditionally_allowed(nested, s)]
    assert leaked == [], f"surgical profile leaked: {leaked}"


def test_clone_new_mask_dropped():
    nested = build_nested(_default())
    # clone must be unconditionally allowed (the CLONE_NEW* arg mask is gone).
    assert is_unconditionally_allowed(nested, "clone")


def test_checked_in_profile_is_current():
    # CI/`glove build` guard: the committed file matches the generator output.
    regenerated = build_nested(_default())
    on_disk = json.loads(NESTED_USERNS_PROFILE.read_text())
    assert on_disk == regenerated


# --- chromium-userns: the `playwright` browser sidecar only -----------------------


def _allowed(profile: dict) -> set[str]:
    return {n for g in profile["syscalls"] for n in g.get("names", []) if is_unconditionally_allowed(profile, n)}


def test_chromium_adds_exactly_its_four_syscalls():
    from glove.runtimes.seccomp.make_profile import CHROMIUM, CHROMIUM_SYSCALLS

    d = _default()
    chromium = json.loads(CHROMIUM.read_text())
    assert chromium == build_nested(d, CHROMIUM_SYSCALLS)  # checked in and current
    assert _allowed(chromium) - _allowed(d) == {"chroot", "clone", "clone3", "unshare"}
    for s in ("mount", "setns", "pivot_root", "umount2", *MUST_STAY_GATED):
        assert not is_unconditionally_allowed(chromium, s), s


def test_chromium_userns_is_a_sidecar_profile_only():
    from glove.compose import SIDECAR_SECCOMP, seccomp_profiles

    assert seccomp_profiles() == {"chromium-userns"} == set(SIDECAR_SECCOMP)
