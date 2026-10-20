"""`glove ext`."""

from typer.testing import CliRunner

from glove.cli import app


def test_ext_lists_the_in_tree_extensions():
    result = CliRunner().invoke(app, ["ext"], env={"COLUMNS": "300"})
    assert result.exit_code == 0, result.output
    assert "gate" in result.output and "library" in result.output and "cli: glove filter …" in result.output
