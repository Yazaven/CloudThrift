"""Core domain models for CloudThrift FinOps intelligence."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enumerations ──────────────────────────────────────────────────────────────


class ResourceType(str, Enum):
    EC2_INSTANCE = "ec2_instance"
    EBS_VOLUME = "ebs_volume"
    ELASTIC_IP = "elastic_ip"
    S3_BUCKET = "s3_bucket"
    RDS_INSTANCE = "rds_instance"
    ELB = "elb"
    LAMBDA_FUNCTION = "lambda_function"
    EBS_SNAPSHOT = "ebs_snapshot"
    AMI = "ami"
    NAT_GATEWAY = "nat_gateway"

    @property
    def label(self) -> str:
        return {
            "ec2_instance": "EC2 Instance",
            "ebs_volume": "EBS Volume",
            "elastic_ip": "Elastic IP",
            "s3_bucket": "S3 Bucket",
            "rds_instance": "RDS Instance",
            "elb": "Load Balancer",
            "lambda_function": "Lambda Function",
            "ebs_snapshot": "EBS Snapshot",
            "ami": "AMI",
            "nat_gateway": "NAT Gateway",
        }[self.value]


class Severity(str, Enum):
    CRITICAL = "CRITICAL"  # >$500/mo waste
    HIGH = "HIGH"          # $100–$500/mo
    MEDIUM = "MEDIUM"      # $20–$100/mo
    LOW = "LOW"            # <$20/mo
    INFO = "INFO"          # Informational only

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }[self.value]

    @property
    def icon(self) -> str:
        return {
            "CRITICAL": "[bold red]●[/]",
            "HIGH": "[red]●[/]",
            "MEDIUM": "[yellow]●[/]",
            "LOW": "[cyan]●[/]",
            "INFO": "[dim]●[/]",
        }[self.value]

    @classmethod
    def from_monthly_cost(cls, cost: float) -> "Severity":
        if cost >= 500:
            return cls.CRITICAL
        if cost >= 100:
            return cls.HIGH
        if cost >= 20:
            return cls.MEDIUM
        if cost > 0:
            return cls.LOW
        return cls.INFO


class FindingStatus(str, Enum):
    OPEN = "open"
    PLANNED = "planned"
    REMEDIATED = "remediated"
    SUPPRESSED = "suppressed"
    FAILED = "failed"


class RemediationAction(str, Enum):
    DELETE_VOLUME = "delete_volume"
    RELEASE_EIP = "release_eip"
    STOP_INSTANCE = "stop_instance"
    TERMINATE_INSTANCE = "terminate_instance"
    DELETE_SNAPSHOT = "delete_snapshot"
    DELETE_BUCKET = "delete_bucket"
    DELETE_ELB = "delete_elb"
    DEREGISTER_AMI = "deregister_ami"
    DELETE_FUNCTION = "delete_function"
    TAG_FOR_REVIEW = "tag_for_review"

    @property
    def is_destructive(self) -> bool:
        return self not in {RemediationAction.STOP_INSTANCE, RemediationAction.TAG_FOR_REVIEW}

    @property
    def verb(self) -> str:
        return {
            "delete_volume": "Delete EBS volume",
            "release_eip": "Release Elastic IP",
            "stop_instance": "Stop EC2 instance",
            "terminate_instance": "Terminate EC2 instance",
            "delete_snapshot": "Delete EBS snapshot",
            "delete_bucket": "Delete S3 bucket",
            "delete_elb": "Delete load balancer",
            "deregister_ami": "Deregister AMI",
            "delete_function": "Delete Lambda function",
            "tag_for_review": "Tag resource for review",
        }[self.value]


class PlanStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"


# ── Finding ───────────────────────────────────────────────────────────────────


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    resource_type: ResourceType
    resource_id: str
    resource_name: str = ""
    resource_arn: str = ""
    region: str
    account_id: str
    severity: Severity
    title: str
    description: str
    estimated_monthly_cost: float = 0.0
    estimated_annual_cost: float = Field(default=0.0)
    tags: dict[str, str] = Field(default_factory=dict)
    age_days: int = 0
    recommendation: str
    remediation_action: RemediationAction
    status: FindingStatus = FindingStatus.OPEN
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if self.estimated_annual_cost == 0.0 and self.estimated_monthly_cost > 0:
            self.estimated_annual_cost = self.estimated_monthly_cost * 12

    @property
    def waste_label(self) -> str:
        mo = self.estimated_monthly_cost
        if mo == 0:
            return "free tier / no charge"
        return f"${mo:,.2f}/mo  (${self.estimated_annual_cost:,.0f}/yr)"

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "resource_type": self.resource_type.label,
            "resource_id": self.resource_id,
            "region": self.region,
            "title": self.title,
            "monthly_waste": f"${self.estimated_monthly_cost:,.2f}",
            "age_days": self.age_days,
            "status": self.status.value,
            "action": self.remediation_action.verb,
        }


# ── Remediation Plan ──────────────────────────────────────────────────────────


class RemediationStep(BaseModel):
    finding_id: str
    action: RemediationAction
    resource_id: str
    resource_type: ResourceType
    region: str
    estimated_savings: float
    is_destructive: bool
    status: str = "pending"
    error: str | None = None
    executed_at: datetime | None = None


class RemediationPlan(BaseModel):
    id: str = Field(default_factory=lambda: "PLAN-" + str(uuid.uuid4())[:6].upper())
    finding_ids: list[str]
    steps: list[RemediationStep]
    dry_run: bool = True
    total_estimated_savings: float = 0.0
    annual_estimated_savings: float = 0.0
    status: PlanStatus = PlanStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    approved_by: str | None = None
    approved_at: datetime | None = None
    executed_at: datetime | None = None
    completed_at: datetime | None = None
    execution_log: list[str] = Field(default_factory=list)
    rollback_actions: list[dict[str, Any]] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        self.total_estimated_savings = sum(s.estimated_savings for s in self.steps)
        self.annual_estimated_savings = self.total_estimated_savings * 12


# ── Scan Result ───────────────────────────────────────────────────────────────


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: "SCAN-" + str(uuid.uuid4())[:6].upper())
    regions: list[str]
    resource_types: list[ResourceType]
    findings: list[Finding] = Field(default_factory=list)
    total_findings: int = 0
    total_monthly_waste: float = 0.0
    total_annual_waste: float = 0.0
    scan_duration_seconds: float = 0.0
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    errors: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        self.total_findings = len(self.findings)
        self.total_monthly_waste = sum(f.estimated_monthly_cost for f in self.findings)
        self.total_annual_waste = self.total_monthly_waste * 12

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    @property
    def findings_by_type(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            key = f.resource_type.label
            result.setdefault(key, []).append(f)
        return result


# ── Audit Entry ───────────────────────────────────────────────────────────────


class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str
    actor: str = "cloudthrift-mcp"
    resource_id: str = ""
    resource_type: str = ""
    region: str = ""
    plan_id: str = ""
    dry_run: bool = True
    success: bool = True
    details: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
