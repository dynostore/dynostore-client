import os
import json
import pytest
from unittest.mock import mock_open
from dynostore.auth.authenticate import DeviceAuthenticator

def test_authenticator_init():
    auth = DeviceAuthenticator(auth_url="localhost:8000")
    assert auth.auth_url == "http://localhost:8000"
    
    auth2 = DeviceAuthenticator(auth_url="https://secure.auth")
    assert auth2.auth_url == "https://secure.auth"

def test_request_user_code(mocker, requests_mock):
    auth = DeviceAuthenticator(auth_url="http://localhost:8095")
    mock_resp = {"verification_uri": "http://localhost:8095/device", "user_code": "ABCD-1234"}
    requests_mock.post("http://localhost:8095/device/code", json=mock_resp)
    
    mocker.patch("builtins.print")
    code = auth.request_user_code()
    assert code == "ABCD-1234"

def test_input_user_token(mocker):
    auth = DeviceAuthenticator()
    mocker.patch("builtins.input", return_value=" token_abc ")
    token = auth.input_user_token()
    assert token == "token_abc"

def test_validate_token_success(mocker, requests_mock):
    auth = DeviceAuthenticator(auth_url="http://localhost:8095")
    mock_resp = {"access_token": "secret_token", "user_token": "my_user_token"}
    requests_mock.post("http://localhost:8095/token/validate", json=mock_resp, status_code=200)
    
    mocker.patch("builtins.print")
    token_data = auth.validate_token("token_abc")
    assert token_data == mock_resp

def test_validate_token_failure(mocker, requests_mock):
    auth = DeviceAuthenticator(auth_url="http://localhost:8095")
    requests_mock.post("http://localhost:8095/token/validate", json={"error": "invalid"}, status_code=400)
    
    mocker.patch("builtins.print")
    token_data = auth.validate_token("bad_token")
    assert token_data is None

def test_save_logout_flow(mocker, tmp_path):
    token_file = tmp_path / "token.json"
    auth = DeviceAuthenticator(token_file=str(token_file))
    
    mocker.patch("builtins.print")
    token_data = {"user_token": "test"}
    
    # Save
    auth.save_token(token_data)
    assert os.path.exists(token_file)
    with open(token_file, "r") as f:
        assert json.load(f) == token_data
        
    # Logout
    auth.logout()
    assert not os.path.exists(token_file)
    
    # Logout again (no file)
    auth.logout() # Should handle missing file gracefully

def test_authenticate_existing_token(mocker, tmp_path):
    token_file = tmp_path / "token.json"
    auth = DeviceAuthenticator(token_file=str(token_file))
    
    mocker.patch("builtins.print")
    token_data = {"user_token": "existing"}
    auth.save_token(token_data)
    
    auth.authenticate(force=False)
    assert auth.token_data == token_data

def test_authenticate_force(mocker, tmp_path):
    token_file = tmp_path / "token.json"
    auth = DeviceAuthenticator(token_file=str(token_file))
    
    mocker.patch("builtins.print")
    mocker.patch.object(auth, "request_user_code")
    mocker.patch.object(auth, "input_user_token", return_value="new_token")
    mock_validate = mocker.patch.object(auth, "validate_token", return_value={"user_token": "new"})
    
    # Put old token
    token_data = {"user_token": "existing"}
    auth.save_token(token_data)
    
    auth.authenticate(force=True)
    assert mock_validate.called
    assert auth.token_data == {"user_token": "new"}
