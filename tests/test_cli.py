import pytest
import sys
from unittest.mock import patch, MagicMock
from dynostore import cli

@pytest.fixture
def mock_sys_argv(monkeypatch):
    def _set_argv(args):
        monkeypatch.setattr(sys, "argv", ["dynostore"] + args)
    return _set_argv

@patch("dynostore.cli.DeviceAuthenticator")
def test_cli_login(mock_authenticator, mock_sys_argv):
    mock_sys_argv(["--server", "localhost:5000", "login"])
    assert cli.main() == 0
    mock_authenticator.assert_called_once_with(auth_url="localhost:5000")
    mock_authenticator.return_value.authenticate.assert_called_once_with(force=False)

@patch("dynostore.cli.DeviceAuthenticator")
def test_cli_logout(mock_authenticator, mock_sys_argv):
    mock_sys_argv(["--server", "localhost:5000", "logout"])
    assert cli.main() == 0
    mock_authenticator.assert_called_once_with(auth_url="localhost:5000")
    mock_authenticator.return_value.logout.assert_called_once()

@patch("dynostore.cli.Client")
def test_cli_exists(mock_client, mock_sys_argv):
    mock_sys_argv(["--server", "localhost:5000", "exists", "my_key"])
    assert cli.main() == 0
    mock_client.assert_called_once_with(metadata_server="localhost:5000")
    mock_client.return_value.exists.assert_called_once_with("my_key")

@patch("dynostore.cli.Client")
def test_cli_evict(mock_client, mock_sys_argv):
    mock_sys_argv(["--server", "localhost:5000", "evict", "my_key"])
    assert cli.main() == 0
    mock_client.return_value.evict.assert_called_once_with("my_key")

@patch("dynostore.cli.Client")
def test_cli_get(mock_client, mock_sys_argv, tmp_path):
    out_file = tmp_path / "out.txt"
    mock_sys_argv(["--server", "localhost:5000", "get", "my_key", "--output", str(out_file)])
    mock_client.return_value.get.return_value = b"downloaded_data"
    
    assert cli.main() == 0
    mock_client.return_value.get.assert_called_once_with("my_key")
    with open(out_file, "rb") as f:
        assert f.read() == b"downloaded_data"

@patch("dynostore.cli.Client")
def test_cli_put(mock_client, mock_sys_argv, tmp_path):
    in_file = tmp_path / "in.txt"
    with open(in_file, "wb") as f:
        f.write(b"upload_data")
        
    mock_sys_argv(["--server", "localhost:5000", "put", str(in_file), "--catalog", "my_cat"])
    
    assert cli.main() == 0
    mock_client.return_value.put.assert_called_once()
    kwargs = mock_client.return_value.put.call_args[1]
    assert kwargs["data"] == b"upload_data"
    assert kwargs["catalog"] == "my_cat"
    assert kwargs["is_encrypted"] is False

@patch("dynostore.cli.Client")
def test_cli_get_catalog(mock_client, mock_sys_argv):
    mock_sys_argv(["--server", "localhost:5000", "get_catalog", "my_cat", "out_dir"])
    assert cli.main() == 0
    mock_client.return_value.get_files_in_catalog.assert_called_once_with("my_cat", output_dir="out_dir")
