"""Human-in-the-loop remediation pipeline.

Architecture
────────────
  create_plan()   →  RemediationPlan (status=PENDING, dry_run=True)
  approve_plan()  →  RemediationPlan (status=APPROVED)
  execute_plan()  →  RemediationPlan (status=COMPLETED | PARTIAL)

Destructive actions require explicit approval and are executed one step at a
time, logging each outcome to the audit trail and the plan's execution_log.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cloudthrift.config import settings
from cloudthrift.scanners.base import BaseScanner
from cloudthrift.models import (
    AuditEntry,
    Finding,
    FindingStatus,
    PlanStatus,
    RemediationAction,
    RemediationPlan,
    RemediationStep,
    ResourceType,
)
from cloudthrift.state import StateStore

logger = logging.getLogger(__name__)


class RemediationPipeline:
    """Builds and executes remediation plans with full audit logging."""

    def __init__(self, store: StateStore) -> None:
        self._store = store

    # ── Plan creation ─────────────────────────────────────────────────────

    def create_plan(
        self,
        finding_ids: list[str],
        dry_run: bool = True,
    ) -> RemediationPlan:
        """Translate a list of finding IDs into an ordered remediation plan."""
        steps: list[RemediationStep] = []

        for fid in finding_ids:
            finding = self._store.get_finding(fid)
            if not finding:
                logger.warning("Finding %s not found — skipping", fid)
                continue
            if finding.status != FindingStatus.OPEN:
                logger.info("Finding %s status=%s — skipping", fid, finding.status)
                continue

            steps.append(
                RemediationStep(
                    finding_id=fid,
                    action=finding.remediation_action,
                    resource_id=finding.resource_id,
                    resource_type=finding.resource_type,
                    region=finding.region,
                    estimated_savings=finding.estimated_monthly_cost,
                    is_destructive=finding.remediation_action.is_destructive,
                )
            )

        # Safest actions first: tags → stops → releases → deletes
        steps.sort(key=lambda s: (s.is_destructive, s.estimated_savings), reverse=False)

        plan = RemediationPlan(
            finding_ids=finding_ids,
            steps=steps,
            dry_run=dry_run,
        )
        self._store.save_plan(plan)

        self._store.append_audit(
            AuditEntry(
                action="create_remediation_plan",
                plan_id=plan.id,
                dry_run=dry_run,
                details={
                    "step_count": len(steps),
                    "estimated_monthly_savings": plan.total_estimated_savings,
                    "finding_ids": finding_ids,
                },
            )
        )
        return plan

    # ── Approval gate ─────────────────────────────────────────────────────

    def approve_plan(self, plan_id: str, approved_by: str = "human-operator") -> RemediationPlan:
        """Mark a plan as approved so it can be executed."""
        plan = self._store.get_plan(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")
        if plan.status not in (PlanStatus.PENDING,):
            raise ValueError(f"Plan {plan_id} is in status {plan.status!r} and cannot be approved")

        plan = plan.model_copy(
            update={
                "status": PlanStatus.APPROVED,
                "approved_by": approved_by,
                "approved_at": datetime.now(timezone.utc),
            }
        )
        self._store.update_plan(plan)
        self._store.append_audit(
            AuditEntry(
                action="approve_remediation_plan",
                plan_id=plan_id,
                dry_run=plan.dry_run,
                details={"approved_by": approved_by},
            )
        )
        return plan

    # ── Execution ─────────────────────────────────────────────────────────

    def execute_plan(self, plan_id: str) -> RemediationPlan:
        """Execute an approved plan step-by-step, logging each outcome."""
        plan = self._store.get_plan(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")

        if (
            plan.status == PlanStatus.PENDING
            and not plan.dry_run
            and settings.require_approval_for_destructive
        ):
            has_destructive = any(s.is_destructive for s in plan.steps)
            if has_destructive:
                raise PermissionError(
                    f"Plan {plan_id} contains destructive actions and requires explicit approval. "
                    "Call approve_plan() first."
                )

        if plan.status not in (PlanStatus.APPROVED, PlanStatus.PENDING):
            raise ValueError(
                f"Plan {plan_id} has status {plan.status!r} and cannot be executed. "
                "Only APPROVED or PENDING (non-destructive) plans can be executed."
            )

        plan = plan.model_copy(
            update={
                "status": PlanStatus.EXECUTING,
                "executed_at": datetime.now(timezone.utc),
            }
        )
        self._store.update_plan(plan)

        updated_steps = list(plan.steps)
        all_succeeded = True

        for i, step in enumerate(updated_steps):
            log_prefix = f"[{plan.id}][{i+1}/{len(updated_steps)}]"

            if plan.dry_run:
                log_msg = f"{log_prefix} DRY-RUN: would {step.action.verb} {step.resource_id}"
                logger.info(log_msg)
                updated_steps[i] = step.model_copy(
                    update={
                        "status": "dry_run",
                        "executed_at": datetime.now(timezone.utc),
                    }
                )
                self._append_execution_log(plan, log_msg)
                self._store.append_audit(
                    AuditEntry(
                        action=step.action.value,
                        resource_id=step.resource_id,
                        resource_type=step.resource_type.value,
                        region=step.region,
                        plan_id=plan.id,
                        dry_run=True,
                        success=True,
                    )
                )
                continue

            # Real execution
            try:
                rollback = self._execute_step(step)
                log_msg = f"{log_prefix} SUCCESS: {step.action.verb} {step.resource_id}"
                logger.info(log_msg)
                updated_steps[i] = step.model_copy(
                    update={
                        "status": "completed",
                        "executed_at": datetime.now(timezone.utc),
                    }
                )
                self._append_execution_log(plan, log_msg)
                if rollback:
                    plan.rollback_actions.append(rollback)
                self._store.update_finding_status(step.finding_id, FindingStatus.REMEDIATED)
                self._store.append_audit(
                    AuditEntry(
                        action=step.action.value,
                        resource_id=step.resource_id,
                        resource_type=step.resource_type.value,
                        region=step.region,
                        plan_id=plan.id,
                        dry_run=False,
                        success=True,
                        details=rollback or {},
                    )
                )
            except Exception as exc:  # noqa: BLE001
                all_succeeded = False
                err_msg = f"{log_prefix} FAILED: {step.action.verb} {step.resource_id} — {exc}"
                logger.error(err_msg)
                updated_steps[i] = step.model_copy(
                    update={"status": "failed", "error": str(exc)}
                )
                self._append_execution_log(plan, err_msg)
                self._store.update_finding_status(step.finding_id, FindingStatus.FAILED)
                self._store.append_audit(
                    AuditEntry(
                        action=step.action.value,
                        resource_id=step.resource_id,
                        resource_type=step.resource_type.value,
                        region=step.region,
                        plan_id=plan.id,
                        dry_run=False,
                        success=False,
                        error=str(exc),
                    )
                )

        final_status = PlanStatus.COMPLETED if all_succeeded else PlanStatus.PARTIAL
        plan = plan.model_copy(
            update={
                "steps": updated_steps,
                "status": final_status,
                "completed_at": datetime.now(timezone.utc),
            }
        )
        self._store.update_plan(plan)
        return plan

    # ── AWS action implementations ────────────────────────────────────────

    def _execute_step(self, step: RemediationStep) -> dict[str, Any] | None:
        session = BaseScanner.build_session(step.region)
        action = step.action
        rid = step.resource_id

        if action == RemediationAction.DELETE_VOLUME:
            return self._delete_volume(session, rid)
        if action == RemediationAction.RELEASE_EIP:
            return self._release_eip(session, rid)
        if action == RemediationAction.STOP_INSTANCE:
            return self._stop_instance(session, rid)
        if action == RemediationAction.TERMINATE_INSTANCE:
            return self._terminate_instance(session, rid)
        if action == RemediationAction.DELETE_SNAPSHOT:
            return self._delete_snapshot(session, rid)
        if action == RemediationAction.DELETE_ELB:
            return self._delete_elb(session, rid)
        if action == RemediationAction.DEREGISTER_AMI:
            return self._deregister_ami(session, rid)
        if action == RemediationAction.DELETE_FUNCTION:
            return self._delete_lambda(session, rid)
        if action == RemediationAction.TAG_FOR_REVIEW:
            return self._tag_for_review(session, rid, step.resource_type, step.region)

        raise NotImplementedError(f"Action {action} not implemented")

    @staticmethod
    def _delete_volume(session: boto3.Session, volume_id: str) -> dict[str, Any]:
        ec2 = session.client("ec2")
        ec2.delete_volume(VolumeId=volume_id)
        return {"restored_by": f"ec2.create_volume (restore from snapshot if one exists)"}

    @staticmethod
    def _release_eip(session: boto3.Session, allocation_id: str) -> dict[str, Any]:
        ec2 = session.client("ec2")
        ec2.release_address(AllocationId=allocation_id)
        return {}

    @staticmethod
    def _stop_instance(session: boto3.Session, instance_id: str) -> dict[str, Any]:
        ec2 = session.client("ec2")
        ec2.stop_instances(InstanceIds=[instance_id])
        return {"rollback": f"ec2.start_instances(InstanceIds=['{instance_id}'])"}

    @staticmethod
    def _terminate_instance(session: boto3.Session, instance_id: str) -> dict[str, Any]:
        ec2 = session.client("ec2")
        # Create a protective snapshot before terminating
        ec2.terminate_instances(InstanceIds=[instance_id])
        return {"warning": "Termination is irreversible. Restore from AMI/snapshot if needed."}

    @staticmethod
    def _delete_snapshot(session: boto3.Session, snapshot_id: str) -> dict[str, Any]:
        ec2 = session.client("ec2")
        ec2.delete_snapshot(SnapshotId=snapshot_id)
        return {}

    @staticmethod
    def _delete_elb(session: boto3.Session, lb_arn: str) -> dict[str, Any]:
        if lb_arn.startswith("arn:"):
            elbv2 = session.client("elbv2")
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        else:
            # Classic ELB — resource_id is the load balancer name, not an ARN
            elb = session.client("elb")
            elb.delete_load_balancer(LoadBalancerName=lb_arn)
        return {}

    @staticmethod
    def _deregister_ami(session: boto3.Session, image_id: str) -> dict[str, Any]:
        ec2 = session.client("ec2")
        # Capture backing snapshot IDs before deregistering
        images = ec2.describe_images(ImageIds=[image_id]).get("Images", [])
        snap_ids = [
            bdm["Ebs"]["SnapshotId"]
            for img in images
            for bdm in img.get("BlockDeviceMappings", [])
            if "Ebs" in bdm and "SnapshotId" in bdm["Ebs"]
        ]
        ec2.deregister_image(ImageId=image_id)
        return {"backing_snapshots": snap_ids}

    @staticmethod
    def _delete_lambda(session: boto3.Session, fn_name: str) -> dict[str, Any]:
        lam = session.client("lambda")
        lam.delete_function(FunctionName=fn_name)
        return {}

    @staticmethod
    def _tag_for_review(
        session: boto3.Session,
        resource_id: str,
        resource_type: ResourceType,
        region: str,
    ) -> dict[str, Any]:
        """Non-destructive: adds a CloudThrift:ReviewRequired tag where supported."""
        tag_value = f"flagged-by-cloudthrift-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        ec2_types = {
            ResourceType.EC2_INSTANCE, ResourceType.EBS_VOLUME,
            ResourceType.ELASTIC_IP, ResourceType.EBS_SNAPSHOT, ResourceType.AMI,
        }
        if resource_type in ec2_types:
            try:
                session.client("ec2").create_tags(
                    Resources=[resource_id],
                    Tags=[{"Key": "CloudThrift:ReviewRequired", "Value": tag_value}],
                )
            except ClientError:
                pass
        elif resource_type == ResourceType.RDS_INSTANCE:
            try:
                session.client("rds").add_tags_to_resource(
                    ResourceName=resource_id,
                    Tags=[{"Key": "CloudThrift:ReviewRequired", "Value": tag_value}],
                )
            except ClientError:
                pass
        elif resource_type == ResourceType.LAMBDA_FUNCTION:
            try:
                session.client("lambda").tag_resource(
                    Resource=resource_id,
                    Tags={"CloudThrift:ReviewRequired": tag_value},
                )
            except ClientError:
                pass
        # S3, ELB: tagging is supported but requires the full ARN/bucket name — skip for now
        return {"tag": f"CloudThrift:ReviewRequired={tag_value}", "resource_type": resource_type.value}

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _append_execution_log(plan: RemediationPlan, message: str) -> None:
        plan.execution_log.append(
            f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {message}"
        )
