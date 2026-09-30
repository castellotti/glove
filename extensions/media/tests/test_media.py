"""`media`: an image layer only — no sidecars, endpoints or network."""

from __future__ import annotations

from helpers import make_cfg

from glove.plan import build_session_plan


def test_media_is_an_image_layer_only(tmp_path):
    for harness, pkg in (("pi", "python3-pil"), ("vibe", "Pillow")):
        work = tmp_path / harness
        work.mkdir()
        cfg = make_cfg(harness=harness, name="s", workdir=str(work), extensions={"media": {}})
        plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))
        assert "ffmpeg" in plan.derived_dockerfile and pkg in plan.derived_dockerfile
        assert [e.name for e in plan.composition.endpoints] == ["llm"]
        assert not plan.composition.fragments
