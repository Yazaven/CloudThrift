"""Tests for the remediation pipeline — plan creation, approval, and execution."""

from __future__ import annotations

import pytest
from moto import mock_aws

from cloudthrift.models import (
    Finding,
    FindingStatus,
    PlanStatus,
    RemediationAction,
    ResourceType,
    Severity,
)
from cloudthrift.remediation.pipeline import RemediationPipeline
from cloudthrift.state import StateStore


def _make_finding(
    rid: str,
    action: RemediationAction = RemediationAction.RELEASE_EIP,
    cost: float = 3.65,
    region: str = "us-east-1",
) -> Finding:
    return Finding(
        resource_type=ResourceType.ELASTIC_IP,
        resource_id=rid,
        region=region,
        account_id="123456789012",
        severity=Severity.LOW,
        title=f"Test finding {rid}",
        description="Test",
        estimated_monthly_cost=cost,
        recommendation="Release.",
        remediation_action=action,
    )


@pytest.fixture
def store_with_findings():
    s = StateStore()
    findings = [
        _make_finding("eip-1", RemediationAction.RELEASE_EIP, 3.65),
        _make_finding("eip-2", RemediationAction.RELEASE_EIP, 3.65),
        _make_finding("vol-1", RemediationAction.DELETE_VOLUME, 50.0),
    ]
    s.upsert_findings(findings)
    return s, findings


class TestCreatePlan:
    def test_plan_includes_all_requested_findings(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)
        plan = p.create_plan([f.id for f in findings])

        assert len(plan.steps) == len(findings)
        assert plan.status == PlanStatus.PENDING
        assert plan.dry_run is True

    def test_skips_nonexistent_findings(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)
        plan = p.create_plan([findings[0].id, "NONEXISTENT"])

        assert len(plan.steps) == 1

    def test_savings_calculated(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)
        plan = p.create_plan([f.id for f in findings])

        expected = sum(f.estimated_monthly_cost for f in findings)
        assert plan.total_estimated_savings == pytest.approx(expected)

    def test_destructive_steps_sorted_last(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)
        plan = p.create_plan([f.id for f in findings])

        # Non-destructive (RELEASE_EIP) should come before destructive (DELETE_VOLUME)
        destructive_indices = [i for i, s in enumerate(plan.steps) if s.is_destructive]
        non_destructive_indices = [i for i, s in enumerate(plan.steps) if not s.is_destructive]
        if destructive_indices and non_destructive_indices:
            assert min(destructive_indices) > max(non_destructive_indices)

    def test_plan_saved_to_store(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)
        plan = p.create_plan([findings[0].id])

        retrieved = store.get_plan(plan.id)
        assert retrieved is not None
        assert retrieved.id == plan.id

    def test_audit_entry_created(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)
        p.create_plan([findings[0].id])

        audit = store.get_audit_log(limit=1)
        assert len(audit) == 1
        assert audit[0].action == "create_remediation_plan"


class TestApprovePlan:
    def test_approval_changes_status(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)
        plan = p.create_plan([findings[0].id])
        approved = p.approve_plan(plan.id, "alice@example.com")

        assert approved.status == PlanStatus.APPROVED
        assert approved.approved_by == "alice@example.com"
        assert approved.approved_at is not None

    def test_approve_nonexistent_plan_raises(self, store_with_findings):
        store, _ = store_with_findings
        p = RemediationPipeline(store)
        with pytest.raises(ValueError, match="not found"):
            p.approve_plan("PLAN-NOPE", "alice")

    def test_double_approve_raises(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)
        plan = p.create_plan([findings[0].id])
        p.approve_plan(plan.id, "alice")
        with pytest.raises(ValueError):
            p.approve_plan(plan.id, "bob")


class TestExecutePlan:
    @mock_aws
    def test_dry_run_execution_no_aws_changes(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)

        # Use a non-destructive finding (TAG_FOR_REVIEW) so no approval needed
        tag_finding = _make_finding(
            "tag-test", RemediationAction.TAG_FOR_REVIEW, 0.0
        )
        store.upsert_findings([tag_finding])

        plan = p.create_plan([tag_finding.id], dry_run=True)
        executed = p.execute_plan(plan.id)

        assert executed.status in (PlanStatus.COMPLETED, PlanStatus.PARTIAL)
        for step in executed.steps:
            assert step.status == "dry_run"

        # Finding status should NOT change in dry-run
        updated_finding = store.get_finding(tag_finding.id)
        assert updated_finding.status == FindingStatus.OPEN

    def test_execute_requires_approval_for_destructive(self, store_with_findings):
        store, findings = store_with_findings
        p = RemediationPipeline(store)

        # Create a plan with a destructive action and live execution
        vol_finding = next(f for f in findings if f.remediation_action == RemediationAction.DELETE_VOLUME)
        plan = p.create_plan([vol_finding.id], dry_run=False)

        # Without approval, should raise PermissionError
        with pytest.raises(PermissionError, match="requires explicit approval"):
            p.execute_plan(plan.id)

    @mock_aws
    def test_execute_after_approval(self, store_with_findings):
        import boto3

        store, findings = store_with_findings
        p = RemediationPipeline(store)

        # Set up mocked EIP
        ec2 = boto3.client("ec2", region_name="us-east-1")
        alloc = ec2.allocate_address(Domain="vpc")

        # Create a finding with the real mocked EIP allocation ID
        eip_f = _make_finding(
            rid=alloc["AllocationId"],
            action=RemediationAction.RELEASE_EIP,
            cost=3.65,
        )
        store.upsert_findings([eip_f])

        plan = p.create_plan([eip_f.id], dry_run=False)
        p.approve_plan(plan.id, "test-operator")
        executed = p.execute_plan(plan.id)

        assert executed.status == PlanStatus.COMPLETED
        step = executed.steps[0]
        assert step.status == "completed"

        # Verify the finding status was updated
        updated = store.get_finding(eip_f.id)
        assert updated.status == FindingStatus.REMEDIATED

    def test_execute_nonexistent_plan_raises(self, store_with_findings):
        store, _ = store_with_findings
        p = RemediationPipeline(store)
        with pytest.raises(ValueError, match="not found"):
            p.execute_plan("PLAN-NOPE")


class TestVisualizationRenderer:
    def test_render_findings_table_returns_string(self):
        from cloudthrift.visualization.renderer import render_findings_table
        findings = [_make_finding(f"r-{i}", cost=float(i * 10)) for i in range(5)]
        output = render_findings_table(findings)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_render_demo_banner(self):
        from cloudthrift.visualization.renderer import render_demo_banner
        banner = render_demo_banner()
        assert "DEMO" in banner

    def test_render_waste_report_markdown(self):
        from cloudthrift.models import ScanResult
        from cloudthrift.visualization.renderer import render_waste_report_markdown

        findings = [_make_finding(f"r-{i}", cost=float(i * 10)) for i in range(3)]
        scan = ScanResult(
            regions=["us-east-1"],
            resource_types=[ResourceType.ELASTIC_IP],
            findings=findings,
        )
        md = render_waste_report_markdown(scan)
        assert "# CloudThrift" in md
        assert "Monthly waste" in md
        assert "|" in md  # has tables
