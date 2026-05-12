"""In-memory state store — findings, plans, and audit log."""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Iterator

from cloudthrift.models import (
    AuditEntry,
    Finding,
    FindingStatus,
    RemediationPlan,
    ScanResult,
)


class StateStore:
    """Thread-safe, in-memory store for the lifetime of the MCP server process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._findings: dict[str, Finding] = {}
        self._plans: dict[str, RemediationPlan] = {}
        self._audit_log: list[AuditEntry] = []
        self._latest_scan: ScanResult | None = None

    # ── Findings ──────────────────────────────────────────────────────────

    def upsert_findings(self, findings: list[Finding]) -> None:
        with self._lock:
            for f in findings:
                self._findings[f.id] = f

    def get_finding(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def get_all_findings(
        self,
        status: FindingStatus | None = None,
        severity: str | None = None,
        resource_type: str | None = None,
        region: str | None = None,
    ) -> list[Finding]:
        with self._lock:
            results = list(self._findings.values())

        if status:
            results = [f for f in results if f.status == status]
        if severity:
            results = [f for f in results if f.severity.value == severity.upper()]
        if resource_type:
            results = [f for f in results if f.resource_type.value == resource_type]
        if region:
            results = [f for f in results if f.region == region]

        return sorted(results, key=lambda f: f.estimated_monthly_cost, reverse=True)

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> bool:
        with self._lock:
            if finding_id not in self._findings:
                return False
            self._findings[finding_id] = self._findings[finding_id].model_copy(
                update={"status": status}
            )
            return True

    def total_monthly_waste(self) -> float:
        with self._lock:
            return sum(
                f.estimated_monthly_cost
                for f in self._findings.values()
                if f.status == FindingStatus.OPEN
            )

    # ── Remediation Plans ─────────────────────────────────────────────────

    def save_plan(self, plan: RemediationPlan) -> None:
        with self._lock:
            self._plans[plan.id] = plan

    def get_plan(self, plan_id: str) -> RemediationPlan | None:
        return self._plans.get(plan_id)

    def get_all_plans(self) -> list[RemediationPlan]:
        with self._lock:
            return sorted(self._plans.values(), key=lambda p: p.created_at, reverse=True)

    def update_plan(self, plan: RemediationPlan) -> None:
        with self._lock:
            self._plans[plan.id] = plan

    # ── Scan Results ──────────────────────────────────────────────────────

    def set_latest_scan(self, scan: ScanResult) -> None:
        with self._lock:
            self._latest_scan = scan

    def get_latest_scan(self) -> ScanResult | None:
        return self._latest_scan

    # ── Audit Log ─────────────────────────────────────────────────────────

    def append_audit(self, entry: AuditEntry) -> None:
        with self._lock:
            self._audit_log.append(entry)
            # Keep the last 1 000 entries in memory
            if len(self._audit_log) > 1_000:
                self._audit_log = self._audit_log[-1_000:]

    def get_audit_log(self, limit: int = 100) -> list[AuditEntry]:
        with self._lock:
            return list(reversed(self._audit_log[-limit:]))

    def audit_entries_since(self, since: datetime) -> Iterator[AuditEntry]:
        with self._lock:
            entries = list(self._audit_log)
        for entry in entries:
            if entry.timestamp >= since:
                yield entry

    # ── Helpers ───────────────────────────────────────────────────────────

    def clear(self) -> None:
        with self._lock:
            self._findings.clear()
            self._plans.clear()
            self._audit_log.clear()
            self._latest_scan = None

    @property
    def finding_count(self) -> int:
        return len(self._findings)


# Module-level singleton — shared across all MCP tool handlers.
store = StateStore()
