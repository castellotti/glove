"""`glove version`."""

from typer.testing import CliRunner

from glove import __version__
from glove.cli import app


def test_version_prints_the_glove_version():
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0 and result.output.strip() == __version__
