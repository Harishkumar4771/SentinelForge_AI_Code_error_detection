"""
HTTP contract tests, driven through the real ASGI app.

These cover what a dashboard actually depends on: the shape of a scan result,
filters that must not lie about counts, the SSE contract including terminal
replay, and the upload boundary. Every scan run here is real -- the mock
provider is deterministic, so this suite asserts on the vulnerable fixture's
known ground truth rather than on mocked responses.
"""

from __future__ import annotations

import io
import json
import pathlib
import zipfile

import pytest

# The three defects the fixture is known to contain.
KNOWN_VERIFIED = {"session.py", "database.py", "files.py"}


@pytest.fixture
def repo_archive(tmp_path) -> pathlib.Path:
    """The vulnerable fixture, zipped the way a real upload would arrive."""
    source = pathlib.Path(__file__).resolve().parents[3] / "test-projects" / "vulnerable-python-app"
    assert source.is_dir(), f"fixture repository missing: {source}"
    archive = tmp_path / "app.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source.rglob("*")):
            if path.is_dir() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            # A single shared top level directory, as macOS/Windows produce.
            zf.write(path, pathlib.Path("vulnerable-python-app") / path.relative_to(source))
    return archive


PROJECT_NAME = "vulnerable-python-app"


async def _upload(client, archive: pathlib.Path) -> dict:
    with archive.open("rb") as fh:
        response = await client.post(
            "/api/projects/upload",
            files={"file": (f"{PROJECT_NAME}.zip", fh, "application/zip")},
        )
    assert response.status_code == 201, response.text
    return response.json()


async def _run_scan(client, project_id: str) -> dict:
    """Start a scan, then follow its SSE stream to completion.

    The stream is how a dashboard learns a scan finished, so waiting on it
    here exercises the real path rather than polling for a side effect.
    """
    import asyncio

    response = await client.post(f"/api/scans/projects/{project_id}", json={"verify": True})
    assert response.status_code in (200, 201, 202), response.text
    accepted = response.json()
    assert accepted["status"] in {"QUEUED", "RUNNING"}
    assert accepted["stream_url"].endswith("/stream")
    scan_id = accepted["scan_id"]

    async with client.stream("GET", f"/api/scans/{scan_id}/stream") as stream:
        assert stream.status_code == 200, await stream.aread()
        async for line in stream.aiter_lines():
            if not line.startswith("data:"):
                continue
            if json.loads(line[5:].strip()).get("phase") == "complete":
                break

    detail = (await client.get(f"/api/scans/{scan_id}")).json()
    assert detail["scan"]["id"] == scan_id
    return detail


class TestHealth:
    async def test_health_reports_configuration(self, api_client) -> None:
        response = await api_client.get("/api/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["provider"]
        assert body["sandbox"]
        assert "running_scans" in body

    async def test_health_never_leaks_secrets(self, api_client) -> None:
        body = (await api_client.get("/api/health")).text.lower()
        for secret in ("key", "password", "token", "secret"):
            assert secret not in body


class TestUpload:
    async def test_valid_archive_becomes_a_project(self, api_client, repo_archive) -> None:
        project = await _upload(api_client, repo_archive)
        assert project["name"] == PROJECT_NAME
        assert project["status"]
        assert project["file_count"] >= 8
        assert project["primary_language"] == "python"

    async def test_non_archive_is_rejected(self, api_client) -> None:
        payload = b"just a text file, not a zip"
        response = await api_client.post(
            "/api/projects/upload", files={"file": ("notes.txt", io.BytesIO(payload), "text/plain")}
        )
        assert response.status_code == 415

    async def test_empty_upload_is_rejected(self, api_client) -> None:
        response = await api_client.post(
            "/api/projects/upload", files={"file": ("empty.zip", io.BytesIO(b""), "application/zip")}
        )
        assert response.status_code == 400

    async def test_corrupt_archive_is_rejected(self, api_client) -> None:
        payload = b"PK\x03\x04 this is not a valid central directory"
        response = await api_client.post(
            "/api/projects/upload", files={"file": ("bad.zip", io.BytesIO(payload), "application/zip")}
        )
        assert response.status_code == 422

    async def test_missing_file_field_is_a_422(self, api_client) -> None:
        assert (await api_client.post("/api/projects/upload")).status_code == 422

    async def test_uploaded_source_path_is_never_exposed(self, api_client, repo_archive) -> None:
        project = await _upload(api_client, repo_archive)
        body = (await api_client.get(f"/api/projects/{project['id']}")).text
        assert str(repo_archive) not in body
        assert "/tmp" not in body, "the client can see server filesystem paths"


class TestProjectEndpoints:
    async def test_projects_are_listed_and_fetchable(self, api_client, repo_archive) -> None:
        project = await _upload(api_client, repo_archive)
        listed = (await api_client.get("/api/projects")).json()
        assert project["id"] in [p["id"] for p in listed]
        fetched = (await api_client.get(f"/api/projects/{project['id']}")).json()
        assert fetched["name"] == project["name"]

    async def test_unknown_project_is_a_404(self, api_client) -> None:
        assert (await api_client.get("/api/projects/does-not-exist")).status_code == 404

    async def test_delete_removes_the_project(self, api_client, repo_archive) -> None:
        project = await _upload(api_client, repo_archive)
        assert (await api_client.delete(f"/api/projects/{project['id']}")).status_code in (200, 204)
        assert (await api_client.get(f"/api/projects/{project['id']}")).status_code == 404

    async def test_project_scans_starts_empty(self, api_client, repo_archive) -> None:
        project = await _upload(api_client, repo_archive)
        assert (await api_client.get(f"/api/projects/{project['id']}/scans")).json() == []


class TestScanLifecycle:
    @pytest.fixture
    async def finished(self, api_client, repo_archive):
        project = await _upload(api_client, repo_archive)
        return await _run_scan(api_client, project["id"])

    async def test_scan_completes(self, finished) -> None:
        scan = finished["scan"]
        assert scan["status"] == "COMPLETED"
        assert scan["security_score"] >= 0
        assert scan["critical_count"] + scan["high_count"] + scan["medium_count"] + scan["low_count"] > 0
        assert scan["tests_generated"] == len(finished["tests"])
        assert scan["verified_fixes"] == len(
            [p for p in finished["patches"] if p["validation_status"] == "VERIFIED"]
        )

    async def test_no_errors_were_recorded(self, finished) -> None:
        assert finished["scan"]["error"] is None

    async def test_every_agent_reported_its_own_outcome(self, finished) -> None:
        agents = {a["agent_name"]: a for a in finished["agents"]}
        assert set(agents) == {"security_agent", "bug_hunter", "testing_agent", "fix_agent"}
        for agent in agents.values():
            assert agent["status"] == "COMPLETED", f"{agent['agent_name']} did not finish: {agent['message']}"
        assert agents["testing_agent"]["metrics"]["tests"] > 0
        assert agents["fix_agent"]["metrics"]["patches"] == 3
        assert agents["security_agent"]["findings_count"] > 0

    async def test_findings_are_returned_with_workflow_state(self, finished) -> None:
        findings = finished["findings"]
        assert findings
        for finding in findings:
            assert finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            assert finding["status"] in {
                "OPEN", "FIX_PROPOSED", "VERIFIED", "FAILED",
                "FALSE_POSITIVE", "REQUIRES_REVIEW",
            }
            assert finding["file_path"] and finding["title"]
            assert finding["detected_by"], "a finding with no source cannot be triaged"

    async def test_the_three_known_defects_are_verified(self, finished) -> None:
        findings = finished["findings"]
        verified = {f["file_path"] for f in findings if f["status"] == "VERIFIED"}
        assert verified == KNOWN_VERIFIED
        assert all(f["verified"] for f in findings if f["status"] == "VERIFIED")

    async def test_patches_carry_verification_evidence(self, finished) -> None:
        patches = finished["patches"]
        assert len(patches) == 3
        for patch in patches:
            assert patch["validation_status"] == "VERIFIED"
            assert patch["verified"] is True
            gates = patch["verification"]["gates"]
            assert len(gates) == 4
            assert {g["gate"] for g in gates} == {
                "reproduced", "applied", "regression", "rescan"
            }
            assert all(gate["passed"] for gate in gates), "a VERIFIED patch has a failed gate"
            assert patch["original_code"] != patch["patched_code"]

    async def test_exploit_tests_are_returned(self, finished) -> None:
        tests = finished["tests"]
        exploits = [t for t in tests if t["is_exploit_test"]]
        assert exploits
        assert all(t["finding_id"] for t in exploits)

    async def test_unverified_findings_remain_open(self, finished) -> None:
        findings = finished["findings"]
        unverified = [f for f in findings if f["status"] != "VERIFIED"]
        assert unverified, "the fixture has more findings than the fix agent handles"
        assert all(f["status"] != "VERIFIED" for f in unverified)

    async def test_local_sandbox_is_reported_as_non_isolated(self, finished) -> None:
        if "docker" in finished["scan"].get("sandbox_backend", "").lower():
            pytest.skip("docker sandbox: isolation is genuine")
        for patch in finished["patches"]:
            assert patch["isolated"] is False, "a host-run patch claimed isolation"


class TestFindingFilters:
    @pytest.fixture
    async def findings(self, api_client, repo_archive):
        project = await _upload(api_client, repo_archive)
        detail = await _run_scan(api_client, project["id"])
        return {**detail, "scan_id": detail["scan"]["id"]}

    @pytest.fixture
    def only_findings(self, findings):
        return findings["findings"]

    @pytest.fixture
    async def scan_id(self, findings):
        return findings["scan_id"]

    async def test_severity_filter_narrows_the_list(self, api_client, scan_id, only_findings) -> None:
        findings = only_findings
        target = findings[0]["severity"]
        filtered = (await api_client.get(f"/api/scans/{scan_id}/findings?severity={target}")).json()
        assert filtered, "the filter returned nothing for a severity that exists"
        assert {f["severity"] for f in filtered} == {target}
        assert len(filtered) <= len(findings)

    async def test_severity_filter_is_case_insensitive(self, api_client, scan_id, only_findings) -> None:
        findings = only_findings
        target = findings[0]["severity"]
        lower = (await api_client.get(f"/api/scans/{scan_id}/findings?severity={target.lower()}")).json()
        assert len(lower) == len(
            [f for f in findings if f["severity"] == target]
        )

    async def test_verified_filter_partitions_the_findings(self, api_client, scan_id, only_findings) -> None:
        findings = only_findings
        verified = (await api_client.get(f"/api/scans/{scan_id}/findings?verified=true")).json()
        unverified = (await api_client.get(f"/api/scans/{scan_id}/findings?verified=false")).json()
        assert len(verified) + len(unverified) == len(findings)
        assert all(f["verified"] for f in verified)
        assert not any(f["verified"] for f in unverified)

    async def test_unknown_filter_value_is_rejected(self, api_client, scan_id) -> None:
        """A typo must not silently look like a correct, empty result."""
        assert (await api_client.get(f"/api/scans/{scan_id}/findings?severity=NOPE")).status_code == 422

    async def test_findings_for_an_unknown_scan_is_a_404(self, api_client) -> None:
        assert (await api_client.get("/api/scans/nope/findings")).status_code == 404

    async def test_booleans_must_be_booleans(self, api_client, scan_id) -> None:
        assert (await api_client.get(f"/api/scans/{scan_id}/findings?verified=maybe")).status_code == 422


class TestEvents:
    async def test_events_are_replayable_after_completion(self, api_client, repo_archive) -> None:
        project = await _upload(api_client, repo_archive)
        detail = await _run_scan(api_client, project["id"])
        events = (await api_client.get(f"/api/scans/{detail['scan']['id']}/events")).json()
        assert events
        assert events[-1]["phase"] == "complete"
        progresses = [e["progress"] for e in events]
        assert progresses == sorted(progresses), "the dashboard progress bar would go backwards"
        assert progresses[-1] == 100.0

    async def test_sse_replays_history_and_closes(self, api_client, repo_archive) -> None:
        project = await _upload(api_client, repo_archive)
        detail = await _run_scan(api_client, project["id"])
        received: list[dict] = []
        async with api_client.stream("GET", f"/api/scans/{detail['scan']['id']}/stream") as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            async for line in response.aiter_lines():
                if not line.startswith("data:"):
                    continue
                event = json.loads(line[5:].strip())
                received.append(event)
                if event.get("phase") == "complete":
                    break
        assert received, "a finished scan replayed no history to a late subscriber"
        assert any(e["phase"] == "ingest" for e in received), "replay skipped early events"
        assert received[-1]["phase"] == "complete"
        assert all(e.get("scan_id") == detail["scan"]["id"] for e in received)

    async def test_sse_frames_are_valid_sse(self, api_client, repo_archive) -> None:
        project = await _upload(api_client, repo_archive)
        detail = await _run_scan(api_client, project["id"])
        async with api_client.stream("GET", f"/api/scans/{detail['scan']['id']}/stream") as response:
            async for line in response.aiter_lines():
                if line.startswith("data:"):
                    # Must parse standalone: a dashboard's EventSource does too.
                    json.loads(line[5:].strip())
                    break
