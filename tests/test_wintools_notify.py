"""Tests for the wintools-mcp POST helpers used by vhir join and case commands."""

import json
from unittest.mock import MagicMock

import yaml

from vhir_cli.commands.join import (
    _push_smb_credentials,
    notify_wintools_case_activated,
    notify_wintools_case_deactivated,
)


def _write_gateway_config(home, url="http://127.0.0.1:8899", token="wt_token_abc"):
    """Write a ~/.vhir/gateway.yaml declaring a wintools-mcp backend."""
    vhir_dir = home / ".vhir"
    vhir_dir.mkdir(parents=True, exist_ok=True)
    (vhir_dir / "gateway.yaml").write_text(
        yaml.dump({"backends": {"wintools-mcp": {"url": url, "bearer_token": token}}})
    )


class _CaptureUrlopen:
    """Stand-in for urllib.request.urlopen that records the requests it sees."""

    def __init__(self, exc=None):
        self.requests = []
        self.kwargs = []
        self.exc = exc

    def __call__(self, req, **kwargs):
        self.requests.append(req)
        self.kwargs.append(kwargs)
        if self.exc is not None:
            raise self.exc
        return MagicMock()


class TestWintoolsPostTargets:
    """Every wintools call must reach its endpoint with the bearer token."""

    def test_push_smb_credentials_posts_to_update_smb(self, tmp_path, monkeypatch):
        monkeypatch.setattr("vhir_cli.commands.join.Path.home", lambda: tmp_path)
        _write_gateway_config(tmp_path)
        cap = _CaptureUrlopen()
        monkeypatch.setattr("urllib.request.urlopen", cap)

        _push_smb_credentials("s3cret", smb_user="vhir-smb")

        assert len(cap.requests) == 1
        req = cap.requests[0]
        assert req.full_url == "http://127.0.0.1:8899/config/update-smb"
        assert req.get_method() == "POST"
        assert req.get_header("Authorization") == "Bearer wt_token_abc"
        assert json.loads(req.data) == {
            "smb_user": "vhir-smb",
            "smb_password": "s3cret",
        }
        assert cap.kwargs[0]["timeout"] == 5

    def test_case_activated_posts_to_cases_activate(self, tmp_path, monkeypatch):
        monkeypatch.setattr("vhir_cli.commands.join.Path.home", lambda: tmp_path)
        _write_gateway_config(tmp_path)
        cap = _CaptureUrlopen()
        monkeypatch.setattr("urllib.request.urlopen", cap)

        assert notify_wintools_case_activated("CASE-1") is True

        assert len(cap.requests) == 1
        req = cap.requests[0]
        assert req.full_url == "http://127.0.0.1:8899/cases/activate"
        assert req.get_method() == "POST"
        assert req.get_header("Authorization") == "Bearer wt_token_abc"
        assert json.loads(req.data) == {"case_id": "CASE-1"}
        assert cap.kwargs[0]["timeout"] == 10

    def test_case_deactivated_posts_to_cases_deactivate(self, tmp_path, monkeypatch):
        monkeypatch.setattr("vhir_cli.commands.join.Path.home", lambda: tmp_path)
        _write_gateway_config(tmp_path)
        cap = _CaptureUrlopen()
        monkeypatch.setattr("urllib.request.urlopen", cap)

        assert notify_wintools_case_deactivated() is True

        assert len(cap.requests) == 1
        req = cap.requests[0]
        assert req.full_url == "http://127.0.0.1:8899/cases/deactivate"
        assert req.get_method() == "POST"
        assert req.get_header("Authorization") == "Bearer wt_token_abc"
        assert json.loads(req.data) == {}
        assert cap.kwargs[0]["timeout"] == 10


class TestWintoolsNotConfigured:
    """Missing config is not a failure, but it must not be reported as success."""

    def test_no_gateway_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr("vhir_cli.commands.join.Path.home", lambda: tmp_path)
        cap = _CaptureUrlopen()
        monkeypatch.setattr("urllib.request.urlopen", cap)

        _push_smb_credentials("s3cret")
        assert notify_wintools_case_activated("CASE-1") is True
        assert notify_wintools_case_deactivated() is True
        assert cap.requests == []

    def test_backend_without_token(self, tmp_path, monkeypatch):
        monkeypatch.setattr("vhir_cli.commands.join.Path.home", lambda: tmp_path)
        _write_gateway_config(tmp_path, token="")
        cap = _CaptureUrlopen()
        monkeypatch.setattr("urllib.request.urlopen", cap)

        _push_smb_credentials("s3cret")
        assert notify_wintools_case_activated("CASE-1") is True
        assert notify_wintools_case_deactivated() is True
        assert cap.requests == []


class TestWintoolsFailures:
    """Communication failures are reported, and the SMB push retries."""

    def test_notify_returns_false_when_unreachable(self, tmp_path, monkeypatch):
        monkeypatch.setattr("vhir_cli.commands.join.Path.home", lambda: tmp_path)
        _write_gateway_config(tmp_path)
        cap = _CaptureUrlopen(exc=ConnectionError("refused"))
        monkeypatch.setattr("urllib.request.urlopen", cap)

        assert notify_wintools_case_activated("CASE-1") is False
        assert notify_wintools_case_deactivated() is False

    def test_push_smb_credentials_retries_three_times(self, tmp_path, monkeypatch):
        monkeypatch.setattr("vhir_cli.commands.join.Path.home", lambda: tmp_path)
        _write_gateway_config(tmp_path)
        cap = _CaptureUrlopen(exc=ConnectionError("refused"))
        monkeypatch.setattr("urllib.request.urlopen", cap)
        sleeps = []
        monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

        _push_smb_credentials("s3cret")

        assert len(cap.requests) == 3
        assert sleeps == [5, 5]
