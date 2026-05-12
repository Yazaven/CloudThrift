"""Configuration management for CloudThrift."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CloudThriftConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CLOUDTHRIFT_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── AWS ────────────────────────────────────────────────────────────────
    aws_regions: list[str] = Field(
        default=["us-east-1"],
        description="AWS regions to scan",
    )
    aws_profile: str | None = Field(None, description="AWS CLI profile name")
    aws_role_arn: str | None = Field(None, description="IAM role ARN to assume for scanning")

    # ── Scan thresholds ────────────────────────────────────────────────────
    stopped_instance_age_days: int = Field(
        default=7,
        description="Flag EC2 instances stopped for longer than this many days",
    )
    unattached_volume_age_days: int = Field(
        default=3,
        description="Flag EBS volumes unattached for longer than this many days",
    )
    idle_elb_request_threshold: int = Field(
        default=100,
        description="Minimum requests/day for an ELB to be considered active",
    )
    idle_elb_days: int = Field(
        default=14,
        description="Flag ELBs that have been below the request threshold for this many days",
    )
    unused_lambda_days: int = Field(
        default=30,
        description="Flag Lambda functions with no invocations in this window",
    )
    old_snapshot_days: int = Field(
        default=90,
        description="Flag EBS snapshots older than this many days",
    )
    s3_inactive_days: int = Field(
        default=90,
        description="Flag S3 buckets with no PUT activity for this many days",
    )

    # ── Cost pricing (USD/unit/month) ───────────────────────────────────────
    # These are approximations; real costs come from Cost Explorer when available.
    eip_monthly_cost: float = Field(default=3.65)
    gp2_gb_monthly_cost: float = Field(default=0.10)
    gp3_gb_monthly_cost: float = Field(default=0.08)
    io1_gb_monthly_cost: float = Field(default=0.125)

    # ── Behaviour ──────────────────────────────────────────────────────────
    demo_mode: bool = Field(
        default=False,
        description="Generate synthetic findings instead of calling AWS (no credentials needed)",
    )
    max_findings_per_scan: int = Field(default=500)
    require_approval_for_destructive: bool = Field(
        default=True,
        description="Always require explicit approval before executing destructive actions",
    )


settings = CloudThriftConfig()
