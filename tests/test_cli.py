from click.testing import CliRunner
from easylic.cli import cli


def test_cli_help():
    """Test CLI help command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output


def test_cli_keygen(tmp_path):
    """Test keygen command."""
    keys_dir = tmp_path / "keys"
    runner = CliRunner()

    result = runner.invoke(cli, ["keygen", "--keys-dir", str(keys_dir)])

    assert result.exit_code == 0
    assert "Keys generated and saved" in result.output
    assert (keys_dir / "server_private.key").exists()
    assert (keys_dir / "server_public.key").exists()


def test_cli_serve_help():
    """Test serve command help."""
    runner = CliRunner()
    result = runner.invoke(cli, ["serve", "--help"])
    assert result.exit_code == 0
    assert "Start the license server" in result.output


def test_cli_generator_help():
    """Test generator command help."""
    runner = CliRunner()
    result = runner.invoke(cli, ["generator", "--help"])
    assert result.exit_code == 0
    assert "Interactive license generator" in result.output