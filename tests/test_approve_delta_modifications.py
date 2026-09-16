"""Tests for the shared delta modification helper in the approve flow."""

from __future__ import annotations

from vhir_cli.commands.approve import _apply_delta_modifications

_IDENTITY = {"examiner": "alice"}
_NOW = "2026-01-01T00:00:00+00:00"


def test_applies_editable_field_and_records_modification():
    """An editable field is written and recorded in examiner_modifications."""
    item = {"id": "F-001", "title": "Old title"}
    entry = {
        "id": "F-001",
        "modifications": {"title": {"original": "Old title", "modified": "New title"}},
    }
    skipped: list = []

    assert _apply_delta_modifications(item, entry, _IDENTITY, _NOW, skipped) is True
    assert item["title"] == "New title"
    assert item["examiner_modifications"]["title"] == {
        "original": "Old title",
        "modified": "New title",
        "modified_by": "alice",
        "modified_at": _NOW,
    }
    assert skipped == []


def test_stale_original_is_skipped_and_item_untouched():
    """A field changed since review aborts the whole entry, applying nothing."""
    item = {"id": "F-001", "title": "Changed by someone else", "source": "disk"}
    entry = {
        "id": "F-001",
        "modifications": {
            "title": {"original": "Old title", "modified": "New title"},
            "source": {"original": "disk", "modified": "memory"},
        },
    }
    skipped: list = []

    assert _apply_delta_modifications(item, entry, _IDENTITY, _NOW, skipped) is False
    assert skipped == [("F-001", "field 'title' changed since review")]
    assert item["title"] == "Changed by someone else"
    assert item["source"] == "disk"
    assert "examiner_modifications" not in item


def test_non_editable_field_is_not_applied():
    """A field outside _DELTA_EDITABLE_FIELDS is verified but never written."""
    item = {"id": "F-001", "status": "DRAFT"}
    entry = {
        "id": "F-001",
        "modifications": {"status": {"original": "DRAFT", "modified": "APPROVED"}},
    }
    skipped: list = []

    assert _apply_delta_modifications(item, entry, _IDENTITY, _NOW, skipped) is True
    assert item["status"] == "DRAFT"
    assert "examiner_modifications" not in item
    assert skipped == []
