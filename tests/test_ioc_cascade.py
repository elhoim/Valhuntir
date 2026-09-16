"""Characterization tests for the IOC approval/rejection cascade.

An IOC follows its source findings: it is auto-approved only when every
source finding is APPROVED, and auto-rejected only when every source
finding is REJECTED. Each entry point (`vhir approve IDS`, `vhir approve`
interactive, `vhir approve --review`, `vhir reject IDS`, `vhir reject
--review`) runs that rule.

These tests pin the rule at every entry point, including the one place
where the entry points deliberately disagree: `--review` resolves sources
through the full case index and ignores source IDs it cannot resolve,
while every other entry point treats an unresolvable source as DRAFT and
therefore holds the IOC back.
"""

import json
from argparse import Namespace
from unittest.mock import patch

import pytest
import yaml

from vhir_cli.approval_auth import setup_password
from vhir_cli.case_io import (
    load_iocs,
    save_findings,
    save_iocs,
    save_timeline,
)
from vhir_cli.commands.approve import _approve_specific, _review_mode, cmd_approve
from vhir_cli.commands.reject import cmd_reject


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal flat case directory structure."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()

    meta = {"case_id": case_id, "name": "Test", "status": "open"}
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)

    with open(case_path / "evidence.json", "w") as f:
        json.dump({"files": []}, f)

    with open(case_path / "todos.json", "w") as f:
        json.dump([], f)

    save_timeline(case_path, [])

    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_path))
    return case_path


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "analyst1",
        "examiner_source": "flag",
        "analyst": "analyst1",
        "analyst_source": "flag",
    }


@pytest.fixture
def config_path(tmp_path):
    return tmp_path / ".vhir" / "config.yaml"


@pytest.fixture(autouse=True)
def isolate_passwords_dir(tmp_path, monkeypatch):
    """Point _PASSWORDS_DIR to temp dir so tests never touch /var/lib/vhir/."""
    d = tmp_path / "passwords"
    d.mkdir(mode=0o700)
    monkeypatch.setattr("vhir_cli.approval_auth._PASSWORDS_DIR", d)
    return d


@pytest.fixture(autouse=True)
def isolate_lockout_file(tmp_path, monkeypatch):
    """Point lockout file to temp dir to avoid cross-test contamination."""
    lockout = tmp_path / ".password_lockout"
    monkeypatch.setattr("vhir_cli.approval_auth._LOCKOUT_FILE", lockout)
    yield lockout
    if lockout.exists():
        lockout.unlink()


@pytest.fixture
def pw_config(config_path):
    """Set up a password for analyst1 and return config_path."""
    with patch(
        "vhir_cli.approval_auth.getpass_prompt",
        side_effect=["testpass1", "testpass1"],
    ):
        setup_password(config_path, "analyst1")
    return config_path


def _stage_finding(case_dir, finding_id="F-tester-001", status="DRAFT"):
    findings = [
        {
            "id": finding_id,
            "status": status,
            "title": "Suspicious process",
            "confidence": "MEDIUM",
            "audit_ids": ["ev-001"],
            "observation": "svchost from cmd",
            "interpretation": "unusual",
            "confidence_justification": "single source",
            "type": "finding",
            "staged": "2026-02-19T12:00:00Z",
            "created_by": "steve",
        }
    ]
    save_findings(case_dir, findings)
    return findings


def _stage_ioc(case_dir, source_findings, status="DRAFT", **extra):
    ioc = {
        "id": "IOC-001",
        "status": status,
        "value": "10.0.0.1",
        "type": "ipv4",
        "content_hash": "0" * 64,
        "source_findings": list(source_findings),
    }
    ioc.update(extra)
    save_iocs(case_dir, [ioc])
    return ioc


def _ioc(case_dir):
    return load_iocs(case_dir)[0]


def _approve_args():
    return Namespace(
        ids=[],
        case=None,
        analyst=None,
        note=None,
        edit=False,
        interpretation=None,
        by=None,
        findings_only=False,
        timeline_only=False,
        review=False,
    )


class TestApproveSpecificCascade:
    """`vhir approve F-1` — approval-only cascade."""

    def test_ioc_approved_when_every_source_approved(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001"])
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        ioc = _ioc(case_dir)
        assert ioc["status"] == "APPROVED"
        assert ioc["approved_by"] == "analyst1"

    def test_ioc_held_when_a_source_id_cannot_be_resolved(
        self, case_dir, identity, pw_config
    ):
        """An unresolvable source counts as DRAFT, so the IOC stays DRAFT."""
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001", "F-deleted-999"])
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        assert _ioc(case_dir)["status"] == "DRAFT"

    def test_manually_reviewed_ioc_is_never_cascaded(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001"], manually_reviewed=True)
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        assert _ioc(case_dir)["status"] == "DRAFT"

    def test_ioc_with_no_sources_is_never_cascaded(self, case_dir, identity, pw_config):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, [])
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        assert _ioc(case_dir)["status"] == "DRAFT"

    def test_approval_does_not_cascade_a_rejection(self, case_dir, identity, pw_config):
        """Approving F-2 must not reject an IOC sourced from rejected F-1."""
        findings = [
            {
                "id": "F-tester-001",
                "status": "REJECTED",
                "title": "Old",
                "type": "finding",
                "created_by": "steve",
            },
            {
                "id": "F-tester-002",
                "status": "DRAFT",
                "title": "New",
                "type": "finding",
                "created_by": "steve",
            },
        ]
        save_findings(case_dir, findings)
        _stage_ioc(case_dir, ["F-tester-001"])
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-002"], identity, pw_config)
        assert _ioc(case_dir)["status"] == "DRAFT"


class TestInteractiveReviewCascade:
    """`vhir approve` interactive — approval and rejection cascade."""

    def _run(self, case_dir, identity, pw_config, keys):
        with patch("builtins.input", side_effect=keys):
            with patch(
                "vhir_cli.commands.approve.Path.home", return_value=case_dir.parent
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"
                ):
                    cmd_approve(_approve_args(), identity)

    def test_ioc_approved_when_every_source_approved(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001"])
        self._run(case_dir, identity, pw_config, ["a"])
        assert _ioc(case_dir)["status"] == "APPROVED"

    def test_ioc_rejected_when_every_source_rejected(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001"])
        self._run(case_dir, identity, pw_config, ["r", "bad data"])
        ioc = _ioc(case_dir)
        assert ioc["status"] == "REJECTED"
        assert ioc["rejection_reason"] == "All source findings rejected"

    def test_ioc_held_when_a_source_id_cannot_be_resolved(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001", "F-deleted-999"])
        self._run(case_dir, identity, pw_config, ["a"])
        assert _ioc(case_dir)["status"] == "DRAFT"


class TestReviewModeCascade:
    """`vhir approve --review` — dashboard delta application."""

    def _write_delta(self, case_dir, entries):
        (case_dir / "pending-reviews.json").write_text(
            json.dumps({"case_id": "INC-2026-TEST", "items": entries})
        )

    def _run(self, case_dir, identity, pw_config):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _review_mode(case_dir, identity, pw_config)

    def test_ioc_approved_when_every_source_approved(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001"])
        self._write_delta(case_dir, [{"id": "F-tester-001", "action": "approve"}])
        self._run(case_dir, identity, pw_config)
        assert _ioc(case_dir)["status"] == "APPROVED"

    def test_ioc_rejected_when_every_source_rejected(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001"])
        self._write_delta(
            case_dir,
            [{"id": "F-tester-001", "action": "reject", "reason": "bad data"}],
        )
        self._run(case_dir, identity, pw_config)
        ioc = _ioc(case_dir)
        assert ioc["status"] == "REJECTED"
        assert ioc["rejection_reason"] == "All source findings rejected"

    def test_unresolvable_source_id_is_ignored_here_unlike_elsewhere(
        self, case_dir, identity, pw_config
    ):
        """Divergence: --review drops sources it cannot resolve and approves.

        Every other entry point treats the same IOC as DRAFT-blocked (see
        TestApproveSpecificCascade). Pinned deliberately so the difference
        is visible to whoever decides which behaviour is correct.
        """
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001", "F-deleted-999"])
        self._write_delta(case_dir, [{"id": "F-tester-001", "action": "approve"}])
        self._run(case_dir, identity, pw_config)
        assert _ioc(case_dir)["status"] == "APPROVED"

    def test_ioc_with_only_unresolvable_sources_is_not_cascaded(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-deleted-999"])
        self._write_delta(case_dir, [{"id": "F-tester-001", "action": "approve"}])
        self._run(case_dir, identity, pw_config)
        assert _ioc(case_dir)["status"] == "DRAFT"

    def test_source_with_explicit_null_status_blocks_the_cascade(
        self, case_dir, identity, pw_config
    ):
        """An explicit ``"status": null`` is unset, not a missing source.

        It must be read as DRAFT and hold the IOC back, exactly as a source
        carrying no status key at all does. Resolving it to ``None`` would
        make it indistinguishable from an unresolvable ID, which ``--review``
        drops from the decision — and the IOC would auto-approve.
        """
        findings = _stage_finding(case_dir)
        findings.append({"id": "F-tester-002", "title": "Unset status", "status": None})
        save_findings(case_dir, findings)

        _stage_ioc(case_dir, ["F-tester-001", "F-tester-002"])
        self._write_delta(case_dir, [{"id": "F-tester-001", "action": "approve"}])
        self._run(case_dir, identity, pw_config)
        assert _ioc(case_dir)["status"] == "DRAFT"

    def test_directly_reviewed_ioc_is_marked_manually_reviewed(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001"])
        self._write_delta(
            case_dir,
            [
                {"id": "F-tester-001", "action": "reject", "reason": "bad"},
                {"id": "IOC-001", "action": "approve"},
            ],
        )
        self._run(case_dir, identity, pw_config)
        ioc = _ioc(case_dir)
        assert ioc["status"] == "APPROVED"
        assert ioc["manually_reviewed"] is True


class TestRejectCascade:
    """`vhir reject F-1` — rejection-only cascade."""

    def _run(self, case_dir, identity, ids, reason="bad data"):
        args = Namespace(ids=ids, reason=reason, case=None, analyst=None, review=False)
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch(
                "vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"
            ):
                cmd_reject(args, identity)

    def test_ioc_rejected_when_every_source_rejected(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001"])
        self._run(case_dir, identity, ["F-tester-001"])
        ioc = _ioc(case_dir)
        assert ioc["status"] == "REJECTED"
        assert ioc["rejection_reason"] == "All source findings rejected"
        assert ioc["rejected_by"] == "analyst1"

    def test_ioc_held_when_a_source_is_still_draft(self, case_dir, identity, pw_config):
        findings = [
            {
                "id": "F-tester-001",
                "status": "DRAFT",
                "title": "One",
                "type": "finding",
                "created_by": "steve",
            },
            {
                "id": "F-tester-002",
                "status": "DRAFT",
                "title": "Two",
                "type": "finding",
                "created_by": "steve",
            },
        ]
        save_findings(case_dir, findings)
        _stage_ioc(case_dir, ["F-tester-001", "F-tester-002"])
        self._run(case_dir, identity, ["F-tester-001"])
        assert _ioc(case_dir)["status"] == "DRAFT"

    def test_rejection_does_not_cascade_an_approval(
        self, case_dir, identity, pw_config
    ):
        """Rejecting F-2 must not approve an IOC sourced from approved F-1."""
        findings = [
            {
                "id": "F-tester-001",
                "status": "APPROVED",
                "title": "Old",
                "type": "finding",
                "created_by": "steve",
            },
            {
                "id": "F-tester-002",
                "status": "DRAFT",
                "title": "New",
                "type": "finding",
                "created_by": "steve",
            },
        ]
        save_findings(case_dir, findings)
        _stage_ioc(case_dir, ["F-tester-001"])
        self._run(case_dir, identity, ["F-tester-002"])
        assert _ioc(case_dir)["status"] == "DRAFT"


class TestInteractiveRejectCascade:
    """`vhir reject --review` — rejection-only cascade."""

    def _run(self, case_dir, identity, keys):
        args = Namespace(ids=[], reason="", case=None, analyst=None, review=True)
        with patch("builtins.input", side_effect=keys):
            with patch(
                "vhir_cli.commands.reject.Path.home", return_value=case_dir.parent
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"
                ):
                    cmd_reject(args, identity)

    def test_ioc_rejected_when_every_source_rejected(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001"])
        self._run(case_dir, identity, ["r", "bad data"])
        ioc = _ioc(case_dir)
        assert ioc["status"] == "REJECTED"
        assert ioc["rejection_reason"] == "All source findings rejected"

    def test_ioc_held_when_a_source_id_cannot_be_resolved(
        self, case_dir, identity, pw_config
    ):
        _stage_finding(case_dir)
        _stage_ioc(case_dir, ["F-tester-001", "F-deleted-999"])
        self._run(case_dir, identity, ["r", "bad data"])
        assert _ioc(case_dir)["status"] == "DRAFT"
