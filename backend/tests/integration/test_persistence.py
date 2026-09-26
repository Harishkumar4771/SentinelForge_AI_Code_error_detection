"""
Persistence round-trip tests.

The database is derived state -- a scan can always be re-run -- so these tests
focus on the properties that would silently corrupt the audit trail if broken:
the right rows attached to the right scan, verification verdicts preserved
verbatim, and nothing lost for a patch whose finding could not be resolved.
"""

from __future__ import annotations

import pytest

from app.models.entities import Finding, Patch, Project, Scan, TestCase
from app.models.enums import ProjectStatus, ScanStatus
from app.services.persistence import ScanPersistence
from app.services.repository import build_snapshot


@pytest.fixture
async def outcome(demo_repo, python_executable):
    from app.services.orchestrator import ScanOrchestrator

    return await ScanOrchestrator().run(
        demo_repo, project_id="demo", python=python_executable
    )


@pytest.fixture
async def stored(db_session, outcome, demo_repo, tmp_path):
    """A scan written to the database, plus the handles needed to read it back."""
    store = ScanPersistence(db_session)
    project = await store.create_project(
        "vulnerable-python-app", storage_path=str(demo_repo)
    )
    await store.sync_files(project, outcome.snapshot or build_snapshot(demo_repo))
    scan = await store.start_scan(project)
    scan.id = outcome.scan_id
    await db_session.flush()
    events = [
        {"phase": "ingest", "message": "test event", "progress": 5.0, "agent": "security_agent"}
    ]
    await store.save_outcome(scan, outcome, events)
    return store, project, scan


class TestProjectAndFiles:
    async def test_project_round_trips(self, db_session) -> None:
        store = ScanPersistence(db_session)
        created = await store.create_project("demo", description="a project")
        fetched = await store.get_project(created.id)
        assert fetched is not None
        assert fetched.name == "demo"
        assert fetched.status == ProjectStatus.ANALYZED.value
        assert created.id in [p.id for p in await store.list_projects()]

    async def test_file_index_is_replaced_not_appended(self, db_session, snapshot) -> None:
        """Re-syncing must not leave rows for files that no longer exist."""
        from sqlalchemy import func, select

        from app.models.entities import FileRecord

        store = ScanPersistence(db_session)
        project = await store.create_project("demo")

        async def file_count() -> int:
            return await db_session.scalar(
                select(func.count())
                .select_from(FileRecord)
                .where(FileRecord.project_id == project.id)
            )

        await store.sync_files(project, snapshot)
        first = await file_count()
        await store.sync_files(project, snapshot)
        assert first > 0
        assert await file_count() == first, "re-syncing duplicated the file index"

    async def test_manifest_and_warnings_are_stored(self, db_session, snapshot) -> None:
        store = ScanPersistence(db_session)
        project = await store.create_project("demo")
        await store.sync_files(project, snapshot)
        assert project.manifest
        assert project.primary_language == snapshot.primary_language
        assert isinstance(project.ingestion_warnings, list)

    async def test_deleting_a_project_cascades(self, db_session, stored) -> None:
        store, project, _ = stored
        from sqlalchemy import func, select

        assert await store.delete_project(project.id) is True
        assert await store.get_project(project.id) is None
        remaining = await db_session.scalar(select(func.count()).select_from(Scan))
        assert remaining == 0, "scans outlived their project"

    async def test_deleting_a_missing_project_reports_false(self, db_session) -> None:
        assert await ScanPersistence(db_session).delete_project("nope") is False


class TestScanRoundTrip:
    async def test_aggregate_counters_match_the_summary(self, stored, outcome) -> None:
        _store, _project, scan = stored
        assert scan.status == ScanStatus.COMPLETED.value
        assert scan.security_score == outcome.summary.security_score
        assert scan.critical_count == outcome.summary.critical
        assert scan.high_count == outcome.summary.high
        assert scan.medium_count == outcome.summary.medium
        assert scan.low_count == outcome.summary.low
        assert scan.verified_fixes == outcome.summary.verified_fixes
        assert scan.tests_generated == len(outcome.test_cases)
        assert scan.duration_seconds and scan.duration_seconds > 0
        assert scan.completed_at is not None

    async def test_findings_are_ordered_by_severity(self, stored) -> None:
        store, _project, scan = stored
        findings = await store.findings_for_scan(scan.id)
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        severities = [order[f.severity] for f in findings]
        assert severities == sorted(severities)

    async def test_every_finding_keeps_its_fingerprint(self, stored, outcome) -> None:
        store, _project, scan = stored
        stored_fingerprints = {f.fingerprint for f in await store.findings_for_scan(scan.id)}
        assert stored_fingerprints == {f.fingerprint for f in outcome.findings}

    async def test_verified_findings_are_persisted(self, stored) -> None:
        store, _project, scan = stored
        findings = await store.findings_for_scan(scan.id)
        verified = [f for f in findings if f.verified]
        assert len(verified) == 3
        assert {f.file_path for f in verified} == {"session.py", "database.py", "files.py"}


class TestPatchesAndTests:
    async def test_patches_carry_the_full_verification_record(self, stored) -> None:
        store, _project, scan = stored
        patches = await store.patches_for_scan(scan.id)
        assert len(patches) == 3
        for patch in patches:
            assert patch.verified is True
            assert patch.validation_status == "VERIFIED"
            assert patch.applied is True
            gates = patch.verification["gates"]
            assert len(gates) == 4
            assert all(g["passed"] for g in gates)
            assert {g["gate"] for g in gates} == {
                "reproduced", "applied", "regression", "rescan"
            }
            # The audit trail must be self-contained.
            assert patch.verification["isolated"] is False
            assert patch.original_code and patch.patched_code
            assert patch.original_code != patch.patched_code

    async def test_every_patch_points_at_a_real_finding(self, stored) -> None:
        store, _project, scan = stored
        finding_ids = {f.id for f in await store.findings_for_scan(scan.id)}
        for patch in await store.patches_for_scan(scan.id):
            assert patch.finding_id in finding_ids

    async def test_exploit_tests_are_linked_to_findings(self, stored) -> None:
        store, _project, scan = stored
        exploits = [t for t in await store.tests_for_scan(scan.id) if t.is_exploit_test]
        assert exploits
        assert all(t.finding_id for t in exploits), "an exploit test lost its finding link"

    async def test_test_code_is_stored_verbatim(self, stored, outcome) -> None:
        store, _project, scan = stored
        stored_tests = {t.name: t.test_code for t in await store.tests_for_scan(scan.id)}
        for test in outcome.test_cases:
            assert stored_tests[test.name] == test.test_code


class TestTimeline:
    async def test_events_are_sequenced(self, stored) -> None:
        store, _project, scan = stored
        events = await store.events_for_scan(scan.id)
        assert [e.seq for e in events] == sorted(e.seq for e in events)

    async def test_agent_executions_are_recorded_with_metrics(self, stored) -> None:
        _store, _project, scan = stored
        from sqlalchemy import select

        from app.models.entities import AgentExecution

        agents = list(
            await stored[0].session.scalars(
                select(AgentExecution).where(AgentExecution.scan_id == scan.id)
            )
        )
        assert {a.agent_name for a in agents} == {
            "security_agent", "bug_hunter", "testing_agent", "fix_agent"
        }
        assert all(a.status == "COMPLETED" for a in agents)
        assert all(a.message for a in agents)


class TestStats:
    async def test_project_stats_counts_rows(self, stored) -> None:
        store, _project, scan = stored
        stats = await store.project_stats()
        assert stats["projects"] == 1
        assert stats["scans"] == 1
        assert stats["findings"] > 0
        assert stats["verified_fixes"] == 3
