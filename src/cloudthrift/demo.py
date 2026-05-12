"""Synthetic demo data generator — no AWS credentials required."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from cloudthrift.models import (
    Finding,
    FindingStatus,
    RemediationAction,
    ResourceType,
    Severity,
)

_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
_ACCOUNT = "123456789012"

random.seed(42)


def _rand_id(prefix: str, length: int = 8) -> str:
    chars = "abcdef0123456789"
    return prefix + "".join(random.choices(chars, k=length))


def _days_ago(n: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=n)


def generate_demo_findings() -> list[Finding]:
    findings: list[Finding] = []

    # ── Stopped EC2 instances ──────────────────────────────────────────────
    for name, itype, days, region in [
        ("api-server-prod",  "m5.xlarge",  45, "us-east-1"),
        ("worker-batch-01",  "c5.2xlarge", 12, "us-west-2"),
        ("bastion-legacy",   "t3.medium",  90, "eu-west-1"),
        ("analytics-runner", "r5.2xlarge", 22, "us-east-1"),
    ]:
        hourly = {"m5.xlarge": 0.192, "c5.2xlarge": 0.34, "t3.medium": 0.0416, "r5.2xlarge": 0.504}
        monthly = hourly[itype] * 24 * 30
        findings.append(Finding(
            resource_type=ResourceType.EC2_INSTANCE,
            resource_id=_rand_id("i-"),
            resource_name=name,
            resource_arn=f"arn:aws:ec2:{region}:{_ACCOUNT}:instance/{_rand_id('i-')}",
            region=region,
            account_id=_ACCOUNT,
            severity=Severity.from_monthly_cost(monthly),
            title=f"Stopped EC2 instance: {name}",
            description=f"Instance {name} ({itype}) has been stopped for {days} days.",
            estimated_monthly_cost=monthly,
            tags={"Name": name, "Environment": "production"},
            age_days=days,
            recommendation="Terminate if unused; create AMI first for safe disposal.",
            remediation_action=RemediationAction.TERMINATE_INSTANCE,
        ))

    # ── Unattached EBS volumes ─────────────────────────────────────────────
    for size, vtype, days, region in [
        (500, "gp2", 30, "us-east-1"),
        (200, "gp3", 14, "us-west-2"),
        (1000, "io1", 60, "eu-west-1"),
        (100, "gp2", 7, "us-east-1"),
        (300, "gp3", 45, "ap-southeast-1"),
    ]:
        per_gb = {"gp2": 0.10, "gp3": 0.08, "io1": 0.125}
        monthly = size * per_gb[vtype]
        findings.append(Finding(
            resource_type=ResourceType.EBS_VOLUME,
            resource_id=_rand_id("vol-"),
            resource_name=f"data-vol-{size}gb",
            resource_arn=f"arn:aws:ec2:{region}:{_ACCOUNT}:volume/{_rand_id('vol-')}",
            region=region,
            account_id=_ACCOUNT,
            severity=Severity.from_monthly_cost(monthly),
            title=f"Unattached EBS volume ({size} GiB {vtype.upper()})",
            description=f"{size} GiB {vtype.upper()} volume unattached for {days} days.",
            estimated_monthly_cost=monthly,
            tags={"Environment": "staging"},
            age_days=days,
            recommendation="Snapshot and delete if data is no longer needed.",
            remediation_action=RemediationAction.DELETE_VOLUME,
        ))

    # ── Elastic IPs ────────────────────────────────────────────────────────
    for region in ["us-east-1", "us-west-2", "eu-west-1"]:
        findings.append(Finding(
            resource_type=ResourceType.ELASTIC_IP,
            resource_id=_rand_id("eipalloc-"),
            resource_name=f"eip-{region}",
            resource_arn=f"arn:aws:ec2:{region}:{_ACCOUNT}:elastic-ip/{_rand_id('eipalloc-')}",
            region=region,
            account_id=_ACCOUNT,
            severity=Severity.LOW,
            title=f"Unattached Elastic IP in {region}",
            description="Elastic IP allocated but not associated with any resource.",
            estimated_monthly_cost=3.65,
            age_days=0,
            recommendation="Release if not actively needed.",
            remediation_action=RemediationAction.RELEASE_EIP,
        ))

    # ── Idle load balancers ────────────────────────────────────────────────
    for name, region in [("alb-staging-api", "us-east-1"), ("alb-old-frontend", "us-west-2")]:
        findings.append(Finding(
            resource_type=ResourceType.ELB,
            resource_id=f"arn:aws:elasticloadbalancing:{region}:{_ACCOUNT}:loadbalancer/app/{name}/abc123",
            resource_name=name,
            resource_arn=f"arn:aws:elasticloadbalancing:{region}:{_ACCOUNT}:loadbalancer/app/{name}/abc123",
            region=region,
            account_id=_ACCOUNT,
            severity=Severity.MEDIUM,
            title=f"Load balancer with no healthy targets: {name}",
            description=f"ALB {name} has 0 healthy targets and costs $16.43/mo.",
            estimated_monthly_cost=16.43,
            age_days=0,
            recommendation="Delete or register healthy targets.",
            remediation_action=RemediationAction.DELETE_ELB,
        ))

    # ── Old snapshots ──────────────────────────────────────────────────────
    for size, days in [(500, 120), (1000, 200), (200, 95)]:
        monthly = size * 0.05
        findings.append(Finding(
            resource_type=ResourceType.EBS_SNAPSHOT,
            resource_id=_rand_id("snap-"),
            resource_name=f"snap-{days}d-old",
            resource_arn=f"arn:aws:ec2:us-east-1:{_ACCOUNT}:snapshot/{_rand_id('snap-')}",
            region="us-east-1",
            account_id=_ACCOUNT,
            severity=Severity.from_monthly_cost(monthly),
            title=f"Old EBS snapshot ({size} GiB, {days} days old)",
            description=f"{size} GiB snapshot is {days} days old and not backing any AMI.",
            estimated_monthly_cost=monthly,
            age_days=days,
            recommendation="Apply DLM policy for automated retention management.",
            remediation_action=RemediationAction.DELETE_SNAPSHOT,
        ))

    # ── Unused Lambda ──────────────────────────────────────────────────────
    for fn_name, runtime, days in [
        ("data-migration-util", "python3.8", 180),
        ("legacy-webhook-handler", "nodejs14.x", 90),
        ("old-cron-processor", "python3.9", 45),
    ]:
        findings.append(Finding(
            resource_type=ResourceType.LAMBDA_FUNCTION,
            resource_id=fn_name,
            resource_name=fn_name,
            resource_arn=f"arn:aws:lambda:us-east-1:{_ACCOUNT}:function:{fn_name}",
            region="us-east-1",
            account_id=_ACCOUNT,
            severity=Severity.INFO,
            title=f"Unused Lambda function: {fn_name}",
            description=f"Function {fn_name} ({runtime}) has had no invocations in {days} days.",
            estimated_monthly_cost=5.0,
            tags={"Runtime": runtime},
            age_days=days,
            recommendation="Delete to reduce IAM attack surface.",
            remediation_action=RemediationAction.DELETE_FUNCTION,
        ))

    # ── RDS stopped ────────────────────────────────────────────────────────
    findings.append(Finding(
        resource_type=ResourceType.RDS_INSTANCE,
        resource_id="analytics-postgres-dev",
        resource_name="analytics-postgres-dev",
        resource_arn=f"arn:aws:rds:us-east-1:{_ACCOUNT}:db:analytics-postgres-dev",
        region="us-east-1",
        account_id=_ACCOUNT,
        severity=Severity.MEDIUM,
        title="Stopped RDS instance: analytics-postgres-dev",
        description="PostgreSQL 14 db.m5.large instance stopped. AWS will auto-restart in ≤7 days.",
        estimated_monthly_cost=0.342 * 24 * 30 * 0.2,
        tags={"Environment": "development", "Team": "analytics"},
        age_days=0,
        recommendation="Snapshot and delete; use Aurora Serverless v2 for dev workloads.",
        remediation_action=RemediationAction.TAG_FOR_REVIEW,
    ))

    return findings
