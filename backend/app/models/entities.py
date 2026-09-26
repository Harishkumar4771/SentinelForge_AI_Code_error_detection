"""
SQLAlchemy ORM models implementing the spec §7 core data model.

Tables: Project, Scan, Finding, TestCase, Patch, AgentExecution
plus FileRecord (ingestion bookkeeping) and ScanEvent (agent timeline).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.enums import (
    AgentStatus,
    FindingStatus,
    ProjectStatus,
    ScanStatus,
    Severity,
    TestStatus,
    TestType,
    ValidationStatus,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


# ----------------------------------------------------------------------
class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), default=ProjectStatus.PENDING.value, nullable=False, index=True
    )

    # Ingestion bookkeeping
    original_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    storage_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    file_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    primary_language: Mapped[str | None] = mapped_column(String(32), nullable=True)
    languages: Mapped[list | None] = mapped_column(JSON, default=list)
    manifest: Mapped[dict | None] = mapped_column(JSON, default=dict)
    ingestion_warnings: Mapped[list | None] = mapped_column(JSON, default=list)

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        order_by="Scan.created_at.desc()",
    )


# ----------------------------------------------------------------------
class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default=ScanStatus.PENDING.value, nullable=False, index=True
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Aggregate security posture
    security_score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    bugs_detected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_generated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_passed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verified_fixes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_fixes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    ai_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    test_cases: Mapped[list["TestCase"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    agent_executions: Mapped[list["AgentExecution"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    events: Mapped[list["ScanEvent"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanEvent.created_at",
    )


# ----------------------------------------------------------------------
class Finding(Base, TimestampMixin):
    """One correlated issue (§8 standard finding format)."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Preserved so a finding survives after its originating test/patch rows
    # are rebuilt by a repair attempt.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="Other", nullable=False)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    owasp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    certainty: Mapped[str] = mapped_column(String(16), default="probable", nullable=False)

    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True, index=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    evidence: Mapped[list | None] = mapped_column(JSON, default=list)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_by: Mapped[list | None] = mapped_column(JSON, default=list)
    tools: Mapped[list | None] = mapped_column(JSON, default=list)

    status: Mapped[str] = mapped_column(
        String(32), default=FindingStatus.OPEN.value, nullable=False, index=True
    )
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_bug: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    patches: Mapped[list["Patch"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_fingerprint", "scan_id", "fingerprint"),
    )


# ----------------------------------------------------------------------
class TestCase(Base, TimestampMixin):
    __tablename__ = "test_cases"

    #: The class name looks like a pytest test class. Without this, pytest
    #: tries to collect it and warns about the __init__ it inherited.
    __test__ = False

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )

    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    test_code: Mapped[str] = mapped_column(Text, default="")
    test_type: Mapped[str] = mapped_column(
        String(32), default=TestType.UNIT.value, nullable=False, index=True
    )
    target_file: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), default=TestStatus.GENERATED.value, nullable=False, index=True
    )
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    # True when the test is meant to *fail* on vulnerable code and pass once
    # the patch lands (the regression test for a specific finding).
    is_exploit_test: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="test_cases")


# ----------------------------------------------------------------------
class Patch(Base, TimestampMixin):
    __tablename__ = "patches"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    original_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    patched_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    files_touched: Mapped[list | None] = mapped_column(JSON, default=list)

    validation_status: Mapped[str] = mapped_column(
        String(32), default=ValidationStatus.PENDING.value, nullable=False, index=True
    )
    validation_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    # JSON blob: test results + rescan results for this attempt.
    verification: Mapped[dict | None] = mapped_column(JSON, default=dict)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    applied: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    repair_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    finding: Mapped[Finding] = relationship(back_populates="patches")

    __table_args__ = (UniqueConstraint("finding_id", "attempt", name="uq_patch_attempt"),)


# ----------------------------------------------------------------------
class AgentExecution(Base, TimestampMixin):
    __tablename__ = "agent_executions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32), default=AgentStatus.PENDING.value, nullable=False, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    metrics: Mapped[dict | None] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="agent_executions")


# ----------------------------------------------------------------------
class ScanEvent(Base):
    """Append-only timeline row powering the agent activity feed (§21)."""

    __tablename__ = "scan_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    seq: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    agent_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    progress: Mapped[float | None] = mapped_column(Float, nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict | None] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="events")

    __table_args__ = (Index("ix_scan_events_scan_seq", "scan_id", "seq"),)


# ----------------------------------------------------------------------
class FileRecord(Base):
    """One discovered source file, used for context building and dedup."""

    __tablename__ = "file_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    language: Mapped[str | None] = mapped_column(String(32), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    line_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_test: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (UniqueConstraint("project_id", "path", name="uq_file_project_path"),)


__all__ = [
    "AgentExecution",
    "FileRecord",
    "Finding",
    "Patch",
    "Project",
    "Scan",
    "ScanEvent",
    "Severity",
    "TestCase",
    "new_id",
    "utcnow",
]
