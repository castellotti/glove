"""`rag` (v3 M6): kstore baked into the image, read-only model/claude-obsidian
mounts, Pi skills, offline env — plus kstore's pure-Python parts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from helpers import make_cfg

from glove.extensions import ExtensionError
from glove.plan import build_session_plan

RAG = Path(__file__).parents[1]
OBSIDIAN_SKILLS = ("wiki-ingest", "wiki-lint", "wiki-mode", "obsidian-markdown", "canvas", "think")


@pytest.fixture
def models(tmp_path):
    d = tmp_path / "models" / "fastembed"
    d.mkdir(parents=True)
    return d


@pytest.fixture
def obsidian(tmp_path):
    d = tmp_path / "claude-obsidian"
    for s in (*OBSIDIAN_SKILLS, "autoresearch"):
        (d / "skills" / s).mkdir(parents=True)
        (d / "skills" / s / "SKILL.md").write_text(f"---\nname: {s}\n---\n")
    return d


def _plan(tmp_path, harness="pi", **rag):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    cfg = make_cfg(harness=harness, name="s", workdir=str(work), extensions={"ocr": {}, "rag": rag})
    return cfg, build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def test_rag_pulls_in_ocr_and_bakes_kstore(tmp_path, models):
    _, plan = _plan(tmp_path, models_dir=str(models))
    comp = plan.composition
    assert [a.name for a in comp.active if a.name in ("ocr", "rag")] == ["ocr", "rag"]
    df = plan.derived_dockerfile
    assert "llama-index-core==0.14.25" in df and "faiss-cpu==1.15.1" in df and "tesseract-ocr" in df
    assert "command -v pip3 >/dev/null || (apt-get update" in df  # Pi's base has no Python
    assert "COPY rag/kstore /opt/glove/rag/kstore" in df and "COPY rag/kstore.sh /usr/local/bin/kstore" in df
    assert "COPY rag/rag-parse /opt/glove/skills/rag/rag-parse" in df
    assert not comp.fragments and [e.name for e in comp.endpoints] == ["llm"]  # offline: no egress


def test_models_dir_is_a_read_only_mount_the_env_points_at(tmp_path, models):
    _, plan = _plan(tmp_path, models_dir=str(models))
    m = next(m for m in plan.mounts if m.container_path == "/mnt/rag-models")
    assert (m.host_path, m.mode) == (str(models.resolve()), "ro")
    env = plan.environment
    assert env["KSTORE_EMBED_CACHE"] == "/mnt/rag-models" and env["HF_HUB_OFFLINE"] == "1"
    assert (env["KSTORE_EMBED_MODEL"], env["KSTORE_QUERY_STORES"]) == ("BAAI/bge-small-en-v1.5", "both")
    assert "CLAUDE_OBSIDIAN_CORE" not in env  # renders empty: not set
    from glove.enforcers.nono.policies import _ro_mounts  # the tool policy may read it
    assert "/mnt/rag-models" in _ro_mounts(plan)


def test_skills_reach_pis_settings(tmp_path, models, obsidian):
    from glove.harnessconfig import render_home

    cfg, plan = _plan(tmp_path, models_dir=str(models), obsidian_dir=str(obsidian))
    cfg.harness_config = {"settings": {"skills": ["/work/my-skill"]}}
    render_home(cfg, plan.profile, tmp_path / "home", plan.model, comp=plan.composition)
    settings = json.loads(next((tmp_path / "home").rglob("settings.json")).read_text())
    assert settings["skills"] == [
        "/opt/glove/skills/rag/rag-parse", "/opt/glove/skills/rag/rag-query",
        *(f"/mnt/rag-obsidian/skills/{s}" for s in OBSIDIAN_SKILLS), "/work/my-skill"]
    assert plan.environment["CLAUDE_OBSIDIAN_CORE"] == "/mnt/rag-obsidian/scripts/claude-obsidian.py"
    assert "wiki-ingest" in dict(plan.composition.rendered_briefs())["rag"]


def test_without_obsidian_dir_no_obsidian_skills_or_brief(tmp_path, models):
    _, plan = _plan(tmp_path, models_dir=str(models))
    assert [d for _, _, d in plan.composition.skills] == ["/opt/glove/skills/rag/rag-parse",
                                                              "/opt/glove/skills/rag/rag-query"]
    assert "wiki-ingest" not in dict(plan.composition.rendered_briefs())["rag"]


def test_a_missing_mounted_skill_fails_at_plan_time(tmp_path, models, obsidian):
    (obsidian / "skills" / "canvas" / "SKILL.md").unlink()
    with pytest.raises(ExtensionError, match=r"'skills/canvas' has no SKILL\.md in mount 'obsidian'"):
        _plan(tmp_path, models_dir=str(models), obsidian_dir=str(obsidian))


def test_vibe_gets_kstore_but_no_skills(tmp_path, models):
    _, plan = _plan(tmp_path, harness="vibe", models_dir=str(models))
    assert "uv pip install --system" in plan.derived_dockerfile and not plan.composition.skills


@pytest.mark.parametrize(("rag", "match"), [
    ({}, "setting 'models_dir' is required"),
    ({"models_dir": "/nonexistent/fastembed"}, "is not a directory"),
    ({"models_dir": "MODELS", "embed_model": "x; rm -rf /"}, "must match"),
])
def test_bad_settings(tmp_path, models, rag, match):
    rag = {k: (str(models) if v == "MODELS" else v) for k, v in rag.items()}
    with pytest.raises(ExtensionError, match=match):
        _plan(tmp_path, **rag)


def test_a_mount_never_exposes_glove_home(tmp_path, monkeypatch):
    home = tmp_path / "gh"
    (home / "models").mkdir(parents=True)
    monkeypatch.setenv("GLOVE_HOME", str(home))
    with pytest.raises(ExtensionError, match="would expose glove's home"):
        _plan(tmp_path, models_dir=str(home / "models"))


def test_fetch_model_reads_the_session_file(tmp_path, monkeypatch):
    sys.path.insert(0, str(RAG.parents[1]))
    from extensions.rag.cli import rag_settings

    (tmp_path / "glove-session.yml").write_text(
        "glove: 3\nharness: pi\nextensions:\n  rag: {models_dir: models/fe, embed_model: a/b}\n")
    assert rag_settings(tmp_path) == (tmp_path / "models" / "fe", "a/b")


# --- kstore (pure Python: extract, chunk, keyword retrieval) ---------------------


@pytest.fixture
def kstore(monkeypatch):
    monkeypatch.syspath_prepend(str(RAG))
    for mod in [m for m in sys.modules if m == "kstore" or m.startswith("kstore.")]:
        monkeypatch.delitem(sys.modules, mod)
    import kstore.compare
    import kstore.extract
    import kstore.locator

    return kstore


def test_extract_text_and_image_with_locators(tmp_path, kstore, monkeypatch):
    sr = tmp_path / "work"
    (sr / "data" / "input").mkdir(parents=True)
    note = sr / "data" / "input" / "note.md"
    note.write_text("Alpha line.\nThe invoice number is 4711.\n")
    res = kstore.extract.extract(note, session_root=sr, out_root=tmp_path / "corpus")
    row = json.loads(res.chunks_path.read_text().splitlines()[0])
    assert row["locator"]["source_path"] == "data/input/note.md" and row["locator"]["extractor"] == "text"
    assert "4711" in row["text"]

    monkeypatch.setattr(kstore.extract, "_image_text", lambda p: "SCANNED TEXT 42\n")
    img = sr / "data" / "input" / "scan.png"
    img.write_bytes(b"\x89PNG")
    res = kstore.extract.extract(img, session_root=sr, out_root=tmp_path / "corpus")
    loc = json.loads(res.chunks_path.read_text().splitlines()[0])["locator"]
    assert (loc["extractor"], loc["confidence"]) == ("tesseract", "medium")


def test_keyword_retrieval_cites_the_source(tmp_path, kstore):
    sr = tmp_path / "work"
    (sr / "data" / "input").mkdir(parents=True)
    for name, text in (("a.txt", "Glove sandboxes coding agents."), ("b.txt", "The invoice number is 4711.")):
        (sr / "data" / "input" / name).write_text(text)
        kstore.extract.extract(sr / "data" / "input" / name, session_root=sr, out_root=kstore.paths.corpus_dir(sr))
    hits, _ = kstore.compare.retrieve_bm25(sr, "raw", "invoice number", 2)
    assert hits[0].locator["source_path"] == "data/input/b.txt"


def test_an_ocrd_copy_is_cited_as_the_original(tmp_path, kstore, monkeypatch):
    sr = tmp_path / "work"
    (sr / "data" / "input").mkdir(parents=True)
    scan = sr / "data" / "input" / "scan.txt"  # stands in for a scanned PDF (no page text)
    scan.write_text("")
    copy = sr / "data" / "store" / "cache" / "ocr" / "scan-ocr.txt"
    copy.parent.mkdir(parents=True)
    copy.write_text("Invoice 4711.")
    digest = kstore.locator.sha256_file(scan)
    res = kstore.extract.extract(copy, session_root=sr, out_root=tmp_path / "corpus", extractor="ocrmypdf",
                                 digest=digest, origin=scan)
    loc = json.loads(res.chunks_path.read_text().splitlines()[0])["locator"]
    assert (loc["source_path"], loc["sha256"]) == ("data/input/scan.txt", digest)
    assert res.doc_id == kstore.extract._doc_id(scan, digest)
