"""
Pydantic response/request models for the HTTP API.

These are deliberately separate from the ORM entities: the API contract should
not change just because a column was added, and internal columns (storage
paths, sandbox internals) should not leak to clients by accident.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    # Path to an already-extracted repository on disk. Used by the CLI/demo and
    # by tests; uploads go through the multipart endpoint instead.
    repository_path: Optional[str] = None


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    status: str
    original_filename: Optional[str] = None
    file_count: int = 0
    total_bytes: int = 0
    primary_language: Optional[str] = None
    languages: list[str] = Field(default_factory=list)
    ingestion_warnings: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    security_score: int = 100
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    bugs_detected: int = 0
    tests_generated: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    verified_fixes: int = 0
    failed_fixes: int = 0
    ai_provider: Optional[str] = None
    duration_seconds: Optional[float] = None
    created_at: datetime
    updated_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    fingerprint: str
    title: str
    description: str = ""
    severity: str
    confidence: float = 0.0
    category: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    certainty: str = "probable"
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    evidence: list[Any] = Field(default_factory=list)
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    detected_by: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    status: str = "OPEN"
    verified: bool = False
    is_bug: bool = False
    created_at: datetime
    updated_at: datetime


class TestCaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    finding_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    test_code: str = ""
    test_type: str = "unit"
    target_file: Optional[str] = None
    status: str = "GENERATED"
    is_exploit_test: bool = False
    duration_ms: Optional[float] = None


class PatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    finding_id: str
    attempt: int = 1
    original_code: Optional[str] = None
    patched_code: Optional[str] = None
    diff: Optional[str] = None
    explanation: Optional[str] = None
    files_touched: list[str] = Field(default_factory=list)
    validation_status: str = "PENDING"
    validation_output: Optional[str] = None
    verification: dict[str, Any] = Field(default_factory=dict)
    verified: bool = False
    applied: bool = False
    duration_ms: Optional[float] = None
    created_at: datetime
    updated_at: datetime


class AgentExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    agent_name: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    message: Optional[str] = None
    findings_count: int = 0
    metrics: dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class ScanEventOut(BaseModel):
    """
    One entry in a scan's timeline.

    The field names deliberately match the live SSE stream (``phase``, ``agent``)
    rather than the database column names: a client that has followed the stream
    and then reconnects to replay history must not have to learn a second
    vocabulary for the same events.
    """

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    scan_id: str
    seq: int
    agent: Optional[str] = Field(default=None, validation_alias="agent_name")
    phase: str = Field(validation_alias="event_type")
    status: Optional[str] = None
    progress: Optional[float] = None
    message: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ScanDetail(BaseModel):
    """Everything the dashboard needs for one scan in a single response."""

    scan: ScanOut
    findings: list[FindingOut] = Field(default_factory=list)
    tests: list[TestCaseOut] = Field(default_factory=list)
    patches: list[PatchOut] = Field(default_factory=list)
    agents: list[AgentExecutionOut] = Field(default_factory=list)


class ScanAccepted(BaseModel):
    """Returned the moment a scan is queued, before any work has happened."""

    scan_id: str
    project_id: str
    status: str
    stream_url: str


class HealthOut(BaseModel):
    status: str
    version: str
    provider: str
    database: str
    sandbox: str
    running_scans: int


__all__ = [
    "AgentExecutionOut",
    "FindingOut",
    "HealthOut",
    "PatchOut",
    "ProjectCreate",
    "ProjectOut",
    "ScanAccepted",
    "ScanDetail",
    "ScanEventOut",
    "ScanOut",
    "TestCaseOut",
]
