"""Unit tests for core domain models."""

from __future__ import annotations

import pytest

from cloudthrift.models import (
    AuditEntry,
    Finding,
    FindingStatus,
    PlanStatus,
    RemediationAction,
    RemediationPlan,
    RemediationStep,
    ResourceType,
    Severity,
)


class TestSeverity:
    def test_from_monthly_cost_critical(self):
        assert Severity.from_monthly_cost(600) == Severity.CRITICAL

    def test_from_monthly_cost_high(self):
        assert Severity.from_monthly_cost(250) == Severity.HIGH

    def test_from_monthly_cost_medium(self):
        assert Severity.from_monthly_cost(50) == Severity.MEDIUM

    def test_from_monthly_cost_low(self):
        assert Severity.from_monthly_cost(10) == Severity.LOW

    def test_from_monthly_cost_info(self):
        assert Severity.from_monthly_cost(0) == Severity.INFO

    def test_color_and_icon(self):
        assert "red" in Severity.CRITICAL.color
        assert "●" in Severity.HIGH.icon or "●" in Severity.CRITICAL.icon


class TestRemediationAction:
    def test_destructive_actions(self):
        assert RemediationAction.DELETE_VOLUME.is_destructive
        assert RemediationAction.TERMINATE_INSTANCE.is_destructive
        assert RemediationAction.DELETE_SNAPSHOT.is_destructive

    def test_non_destructive_actions(self):
        assert not RemediationAction.STOP_INSTANCE.is_destructive
        assert not RemediationAction.TAG_FOR_REVIEW.is_destructive

    def test_verb(self):
        assert "Delete" in RemediationAction.DELETE_VOLUME.verb
        assert "Stop" in RemediationAction.STOP_INSTANCE.verb


class TestFinding:
    def test_annual_cost_auto_calculated(self):
        f = Finding(
            resource_type=ResourceType.EBS_VOLUME,
            resource_id="vol-123",
            region="us-east-1",
            account_id="123456789012",
            severity=Severity.MEDIUM,
            title="Test",
            description="Test finding",
            estimated_monthly_cost=50.0,
            recommendation="Delete it.",
            remediation_action=RemediationAction.DELETE_VOLUME,
        )
        assert f.estimated_annual_cost == pytest.approx(600.0)

    def test_waste_label_formatting(self):
        f = Finding(
            resource_type=ResourceType.ELASTIC_IP,
            resource_id="eipalloc-123",
            region="us-east-1",
            account_id="123456789012",
            severity=Severity.LOW,
            title="Idle EIP",
            description="EIP not in use.",
            estimated_monthly_cost=3.65,
            recommendation="Release it.",
            remediation_action=RemediationAction.RELEASE_EIP,
        )
        label = f.waste_label
        assert "$3.65" in label
        assert "/mo" in label

    def test_to_summary_dict_keys(self):
        f = Finding(
            resource_type=ResourceType.EC2_INSTANCE,
            resource_id="i-abc123",
            region="us-east-1",
            account_id="123456789012",
            severity=Severity.HIGH,
            title="Stopped instance",
            description="Instance stopped.",
            estimated_monthly_cost=120.0,
            recommendation="Terminate.",
            remediation_action=RemediationAction.TERMINATE_INSTANCE,
        )
        d = f.to_summary_dict()
        expected_keys = {"id", "severity", "resource_type", "resource_id", "region",
                         "title", "monthly_waste", "age_days", "status", "action"}
        assert expected_keys.issubset(d.keys())

    def test_unique_ids(self):
        ids = {
            Finding(
                resource_type=ResourceType.S3_BUCKET,
                resource_id=f"bucket-{i}",
                region="us-east-1",
                account_id="123456789012",
                severity=Severity.INFO,
                title="Empty bucket",
                description="No objects.",
                recommendation="Delete.",
                remediation_action=RemediationAction.DELETE_BUCKET,
            ).id
            for i in range(100)
        }
        assert len(ids) == 100


class TestRemediationPlan:
    def test_total_savings_calculated(self):
        steps = [
            RemediationStep(
                finding_id="A1",
                action=RemediationAction.DELETE_VOLUME,
                resource_id="vol-1",
                resource_type=ResourceType.EBS_VOLUME,
                region="us-east-1",
                estimated_savings=50.0,
                is_destructive=True,
            ),
            RemediationStep(
                finding_id="A2",
                action=RemediationAction.RELEASE_EIP,
                resource_id="eip-1",
                resource_type=ResourceType.ELASTIC_IP,
                region="us-east-1",
                estimated_savings=3.65,
                is_destructive=False,
            ),
        ]
        plan = RemediationPlan(finding_ids=["A1", "A2"], steps=steps, dry_run=True)
        assert plan.total_estimated_savings == pytest.approx(53.65)
        assert plan.annual_estimated_savings == pytest.approx(53.65 * 12)

    def test_plan_id_prefix(self):
        plan = RemediationPlan(finding_ids=[], steps=[])
        assert plan.id.startswith("PLAN-")

    def test_default_status(self):
        plan = RemediationPlan(finding_ids=[], steps=[])
        assert plan.status == PlanStatus.PENDING


class TestAuditEntry:
    def test_audit_entry_defaults(self):
        entry = AuditEntry(action="scan_resources")
        assert entry.dry_run is True
        assert entry.success is True
        assert entry.actor == "cloudthrift-mcp"
        assert entry.timestamp is not None
