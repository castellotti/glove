"""`ocr`: an image layer (tesseract/ocrmypdf/poppler + `glove-ocr`) — no sidecars, endpoints or network."""

from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path

import pytest
from helpers import make_cfg

from glove.extensions import ExtensionError
from glove.plan import build_session_plan

BIN = Path(__file__).parents[1] / "bin" / "glove-ocr"


def _plan(tmp_path, harness="pi", ocr=None, extra=None):
    work = tmp_path / harness
    work.mkdir(exist_ok=True)
    cfg = make_cfg(harness=harness, name="s", workdir=str(work), extensions={"ocr": ocr or {}, **(extra or {})})
    return build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


@pytest.mark.parametrize("harness", ["pi", "vibe"])
def test_ocr_is_an_image_layer_only(tmp_path, harness):
    plan = _plan(tmp_path, harness)
    df = plan.derived_dockerfile
    for pkg in ("tesseract-ocr", "tesseract-ocr-eng", "ocrmypdf", "poppler-utils", "ghostscript", "file"):
        assert f" {pkg}" in df
    assert "COPY ocr/glove-ocr /usr/local/bin/glove-ocr" in df
    assert [e.name for e in plan.composition.endpoints] == ["llm"]
    assert not plan.composition.fragments and not plan.composition.harness_mounts


def test_languages_expand_to_packages(tmp_path):
    df = _plan(tmp_path, ocr={"languages": ["eng", "deu", "chi-sim"]}).derived_dockerfile
    line = next(x for x in df.splitlines() if "tesseract-ocr" in x)
    assert "tesseract-ocr-eng tesseract-ocr-deu tesseract-ocr-chi-sim ocrmypdf" in line


@pytest.mark.parametrize("langs", [["eng; curl x"], ["ENG"], [""], [3]])
def test_languages_are_package_suffixes_only(tmp_path, langs):
    with pytest.raises(ExtensionError, match="must match"):
        _plan(tmp_path, ocr={"languages": langs})


def test_brief_follows_the_models_vision(tmp_path):
    plan = _plan(tmp_path, ocr={"languages": ["eng", "chi-sim"]})
    brief = dict(plan.composition.rendered_briefs())["ocr"]
    assert "--lang eng+chi_sim" in brief and "xargs -P 3" in brief
    assert ("You can see images" in brief) == bool(plan.composition.slot_exports("inference")["capabilities"]["vision"])


def _cli():
    loader = importlib.machinery.SourceFileLoader("glove_ocr", str(BIN))
    spec = importlib.util.spec_from_loader("glove_ocr", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_page_ranges():
    cli = _cli()
    assert cli._pages(None, 3) == [1, 2, 3]
    assert cli._pages("2-3,7,9", 8) == [2, 3, 7]  # out of range pages are dropped
    assert cli._pages("1", 0) == []


def test_unsupported_files_are_refused(tmp_path):
    f = tmp_path / "x.docx"
    f.write_text("x")
    with pytest.raises(SystemExit, match=r"unsupported file type \.docx"):
        _cli().main([str(f)])
