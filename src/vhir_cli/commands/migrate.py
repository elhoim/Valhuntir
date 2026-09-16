"""Migrate cases from old examiners/ directory structure to flat layout.

Usage:
  vhir case migrate [--case-dir <path>] [--examiner <name>] [--import-all]

Detects the old examiners/ subdirectory structure and flattens it:
- Re-IDs findings: F-001 → F-alice-001
- Re-IDs timeline: T-001 → T-alice-001
- Re-IDs TODOs: TODO-001 → TODO-alice-001
- Moves data files to case root
- Updates cross-references in approvals and actions
- Preserves original examiners/ as backup (renamed to examiners.bak/)

With --import-all: re-IDs and merges all other examiners' data too.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone

import yaml

from vhir_cli.case_io import (
    _atomic_write,
    get_case_dir,
    get_examiner,
)


def cmd_migrate(args, identity: dict) -> None:
    """Migrate a case from examiners/ structure to flat layout."""
    case_dir = get_case_dir(getattr(args, "case", None))
    examiner = getattr(args, "examiner", None) or get_examiner(case_dir)
    import_all = getattr(args, "import_all", False)

    examiners_root = case_dir / "examiners"
    if not examiners_root.is_dir():
        print("No examiners/ directory found. Case may already be in flat layout.")
        return

    exam_dir = examiners_root / examiner
    if not exam_dir.is_dir():
        available = [
            d.name
            for d in examiners_root.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]
        print(f"Examiner directory not found: {exam_dir}", file=sys.stderr)
        if available:
            print(f"Available examiners: {', '.join(available)}", file=sys.stderr)
        sys.exit(1)

    print(f"Migrating case: {case_dir.name}")
    print(f"Primary examiner: {examiner}")

    # Collect all examiners to process
    examiners_to_process = [examiner]
    if import_all:
        for d in sorted(examiners_root.iterdir()):
            if d.is_dir() and not d.name.startswith(".") and d.name != examiner:
                examiners_to_process.append(d.name)
        print(f"Import all: merging {len(examiners_to_process)} examiner(s)")

    # --- Phase 1: Re-ID and collect data from each examiner ---

    all_findings = []
    all_timeline = []
    all_todos = []
    all_actions = []
    all_approvals = []
    id_map = {}  # old_id -> new_id for cross-reference updates

    for exam in examiners_to_process:
        edir = examiners_root / exam
        print(f"\n  Processing {exam}...")

        # Findings, timeline and TODOs share one re-ID shape; the table keeps
        # the three files from drifting apart. The two flags spell out where
        # they legitimately differ: TODOs carry no modified_at (nothing merges
        # or exports them by timestamp) but do resolve their related_findings
        # here, against this examiner's own IDs.
        for fname, label, prefix, id_field, bucket, stamp_modified, remap_refs in (
            ("findings.json", "Findings", "F", "id", all_findings, True, False),
            ("timeline.json", "Timeline", "T", "id", all_timeline, True, False),
            ("todos.json", "TODOs", "TODO", "todo_id", all_todos, False, True),
        ):
            data_file = edir / fname
            if not data_file.exists():
                continue
            try:
                records = json.loads(data_file.read_text())
            except (json.JSONDecodeError, OSError) as e:
                print(f"    WARNING: could not read {data_file}: {e}", file=sys.stderr)
                records = []
            for rec in records:
                old_id = rec.get(id_field, "")
                new_id = _re_id(old_id, prefix, exam)
                id_map[old_id] = new_id
                id_map[f"{exam}/{old_id}"] = new_id  # Also map scoped form
                rec[id_field] = new_id
                rec["examiner"] = exam
                if stamp_modified:
                    rec.setdefault(
                        "modified_at",
                        rec.get("staged", datetime.now(timezone.utc).isoformat()),
                    )
                if remap_refs:
                    # Update related_findings references
                    rec["related_findings"] = [
                        id_map.get(r, r) for r in rec.get("related_findings", [])
                    ]
                bucket.append(rec)
            print(f"    {label}: {len(records)} (re-IDed)")

        # Actions
        actions_file = edir / "actions.jsonl"
        if actions_file.exists():
            with open(actions_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        # Update finding references in action entries
                        _re_id_refs(entry, id_map)
                        all_actions.append(entry)
                    except json.JSONDecodeError:
                        pass

        # Approvals
        approvals_file = edir / "approvals.jsonl"
        if approvals_file.exists():
            with open(approvals_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        # Update item_id reference
                        old_ref = entry.get("item_id", "")
                        entry["item_id"] = id_map.get(old_ref, old_ref)
                        all_approvals.append(entry)
                    except json.JSONDecodeError:
                        pass

    # --- Phase 2: Update cross-references with final id_map ---
    for t in all_todos:
        t["related_findings"] = [
            id_map.get(r, r) for r in t.get("related_findings", [])
        ]
    for t in all_timeline:
        if "related_findings" in t:
            t["related_findings"] = [id_map.get(r, r) for r in t["related_findings"]]
    for entry in all_actions:
        _re_id_refs(entry, id_map)

    # --- Phase 3: Write flat files to case root ---
    print("\nWriting flat case directory...")

    # Check for existing flat files (don't overwrite)
    for fname in ("findings.json", "timeline.json", "todos.json"):
        existing = case_dir / fname
        if existing.exists():
            data = json.loads(existing.read_text())
            if data:
                print(
                    f"  WARNING: {fname} already has data at case root. Skipping migration.",
                    file=sys.stderr,
                )
                sys.exit(1)

    _atomic_write(
        case_dir / "findings.json", json.dumps(all_findings, indent=2, default=str)
    )
    _atomic_write(
        case_dir / "timeline.json", json.dumps(all_timeline, indent=2, default=str)
    )
    _atomic_write(case_dir / "todos.json", json.dumps(all_todos, indent=2, default=str))

    # Merge actions
    if all_actions:
        with open(case_dir / "actions.jsonl", "a", encoding="utf-8") as f:
            for entry in all_actions:
                f.write(json.dumps(entry, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())

    # Merge approvals
    if all_approvals:
        with open(case_dir / "approvals.jsonl", "a", encoding="utf-8") as f:
            for entry in all_approvals:
                f.write(json.dumps(entry, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())

    # Merge audit directories
    (case_dir / "audit").mkdir(exist_ok=True)
    for exam in examiners_to_process:
        audit_dir = examiners_root / exam / "audit"
        if audit_dir.is_dir():
            for jsonl_file in audit_dir.glob("*.jsonl"):
                dest = case_dir / "audit" / jsonl_file.name
                if dest.exists():
                    # Append
                    with open(dest, "a", encoding="utf-8") as f:
                        f.write(jsonl_file.read_text())
                else:
                    shutil.copy2(jsonl_file, dest)

    # Copy evidence.json if it exists (merge from primary examiner)
    evidence_file = examiners_root / examiner / "evidence.json"
    if evidence_file.exists() and not (case_dir / "evidence.json").exists():
        shutil.copy2(evidence_file, case_dir / "evidence.json")

    # Copy evidence_access.jsonl
    access_file = examiners_root / examiner / "evidence_access.jsonl"
    if access_file.exists():
        with open(case_dir / "evidence_access.jsonl", "a", encoding="utf-8") as f:
            f.write(access_file.read_text())

    # --- Phase 4: Update CASE.yaml ---
    meta_file = case_dir / "CASE.yaml"
    if meta_file.exists():
        meta = yaml.safe_load(meta_file.read_text()) or {}
        # Remove old multi-examiner fields
        meta.pop("mode", None)
        meta.pop("team", None)
        meta.pop("created_by", None)
        meta["migrated_at"] = datetime.now(timezone.utc).isoformat()
        _atomic_write(meta_file, yaml.dump(meta, default_flow_style=False))

    # Create extractions dir if missing (renamed from extracted)
    (case_dir / "extractions").mkdir(exist_ok=True)

    # --- Phase 5: Backup old structure ---
    backup_dir = case_dir / "examiners.bak"
    if backup_dir.exists():
        print(
            f"  WARNING: {backup_dir} already exists. Not overwriting backup.",
            file=sys.stderr,
        )
    else:
        examiners_root.rename(backup_dir)
        print("  Backed up examiners/ → examiners.bak/")

    # --- Summary ---
    print("\nMigration complete:")
    print(f"  Findings: {len(all_findings)}")
    print(f"  Timeline: {len(all_timeline)}")
    print(f"  TODOs: {len(all_todos)}")
    print(f"  Actions: {len(all_actions)}")
    print(f"  Approvals: {len(all_approvals)}")
    print(f"  ID mappings: {len(id_map)}")


def _re_id(old_id: str, prefix: str, examiner: str) -> str:
    """Re-ID from old format to new: F-001 → F-alice-001.

    If already in new format (F-alice-001), return as-is.
    """
    # Already in new format?
    new_pattern = f"^{re.escape(prefix)}-[a-z0-9-]+-\\d+$"
    if re.match(new_pattern, old_id):
        return old_id

    # Extract sequence number
    match = re.match(f"^{re.escape(prefix)}-(\\d+)$", old_id)
    if match:
        seq = int(match.group(1))
        return f"{prefix}-{examiner}-{seq:03d}"

    # Fallback: just prefix with examiner
    return f"{prefix}-{examiner}-{old_id.split('-')[-1] if '-' in old_id else '001'}"


def _re_id_refs(entry: dict, id_map: dict) -> None:
    """Update old-format finding/timeline references in an action or log entry.

    Scans common reference fields and replaces old IDs with new IDs
    using the id_map built during migration.
    """
    for key in ("finding_id", "item_id", "audit_id"):
        val = entry.get(key, "")
        if val and val in id_map:
            entry[key] = id_map[val]
    for key in ("related_findings", "finding_ids"):
        refs = entry.get(key)
        if isinstance(refs, list):
            entry[key] = [id_map.get(r, r) for r in refs]
