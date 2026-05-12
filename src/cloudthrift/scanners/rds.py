"""RDS instance scanner — stopped and low-utilisation databases."""

from __future__ import annotations

from datetime import datetime, timezone

from cloudthrift.config import settings
from cloudthrift.models import Finding, RemediationAction, ResourceType, Severity
from cloudthrift.scanners.base import BaseScanner

# Approximate on-demand pricing for common RDS instance classes ($/hr, single-AZ).
# Multi-AZ doubles this cost.
_RDS_HOURLY: dict[str, float] = {
    "db.t3.micro": 0.034, "db.t3.small": 0.068, "db.t3.medium": 0.136,
    "db.t3.large": 0.272, "db.t3.xlarge": 0.544, "db.t3.2xlarge": 1.088,
    "db.m5.large": 0.342, "db.m5.xlarge": 0.684, "db.m5.2xlarge": 1.368,
    "db.m5.4xlarge": 2.736, "db.r5.large": 0.48, "db.r5.xlarge": 0.96,
    "db.r5.2xlarge": 1.92,
}


def _age_days(dt: datetime) -> int:
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (now - dt).days)


class RDSScanner(BaseScanner):
    """Detects stopped RDS instances and idle clusters."""

    resource_type = ResourceType.RDS_INSTANCE

    def scan(self) -> list[Finding]:
        rds = self.client("rds")
        account = self.account_id
        findings: list[Finding] = []

        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_status = db.get("DBInstanceStatus", "")
                instance_class = db.get("DBInstanceClass", "db.t3.micro")
                db_id = db.get("DBInstanceIdentifier", "")
                engine = db.get("Engine", "")
                multi_az = db.get("MultiAZ", False)
                hourly = _RDS_HOURLY.get(instance_class, 0.342) * (2.0 if multi_az else 1.0)
                monthly_cost = hourly * 24 * 30
                tags = self._get_rds_tags(rds, db.get("DBInstanceArn", ""))

                # ── Stopped instances ─────────────────────────────────────
                if db_status == "stopped":
                    # AWS auto-restarts stopped RDS after 7 days — clarify that risk.
                    findings.append(
                        Finding(
                            resource_type=ResourceType.RDS_INSTANCE,
                            resource_id=db_id,
                            resource_name=tags.get("Name", db_id),
                            resource_arn=db.get("DBInstanceArn", ""),
                            region=self.region,
                            account_id=account,
                            severity=Severity.from_monthly_cost(monthly_cost),
                            title=f"Stopped RDS instance: {db_id}",
                            description=(
                                f"RDS {engine} instance {db_id} ({instance_class}) is stopped. "
                                f"AWS will automatically restart stopped RDS instances after 7 days, "
                                f"resuming charges of ${monthly_cost:,.2f}/mo. Storage costs still "
                                f"accrue during the stopped state."
                            ),
                            estimated_monthly_cost=monthly_cost * 0.2,  # storage-only costs
                            tags=tags,
                            age_days=0,
                            recommendation=(
                                "Create a final snapshot and delete the instance if it is no longer "
                                "needed. Restore from snapshot when required. Consider Aurora "
                                "Serverless v2 for workloads with intermittent demand."
                            ),
                            remediation_action=RemediationAction.TAG_FOR_REVIEW,
                            metadata={
                                "engine": engine,
                                "engine_version": db.get("EngineVersion", ""),
                                "instance_class": instance_class,
                                "multi_az": multi_az,
                                "allocated_storage_gb": db.get("AllocatedStorage", 0),
                                "db_status": db_status,
                            },
                        )
                    )

                # ── Single-AZ production database (availability risk) ──────
                elif db_status == "available" and not multi_az:
                    env = tags.get("Environment", tags.get("Env", "")).lower()
                    if env in ("prod", "production"):
                        findings.append(
                            Finding(
                                resource_type=ResourceType.RDS_INSTANCE,
                                resource_id=db_id,
                                resource_name=tags.get("Name", db_id),
                                resource_arn=db.get("DBInstanceArn", ""),
                                region=self.region,
                                account_id=account,
                                severity=Severity.HIGH,
                                title=f"Single-AZ production RDS: {db_id}",
                                description=(
                                    f"Production RDS instance {db_id} is running in a single "
                                    f"Availability Zone. An AZ failure will cause a multi-minute "
                                    f"outage with data loss risk. Multi-AZ adds ~${monthly_cost:,.2f}/mo "
                                    f"(doubles the instance cost) but provides automatic failover."
                                ),
                                estimated_monthly_cost=0.0,
                                tags=tags,
                                age_days=_age_days(db.get("InstanceCreateTime", datetime.now(timezone.utc))),
                                recommendation=(
                                    "Enable Multi-AZ for production RDS instances to achieve "
                                    "<120s automatic failover RTO and zero RPO with synchronous replication."
                                ),
                                remediation_action=RemediationAction.TAG_FOR_REVIEW,
                                metadata={
                                    "engine": engine,
                                    "instance_class": instance_class,
                                    "multi_az": False,
                                    "allocated_storage_gb": db.get("AllocatedStorage", 0),
                                },
                            )
                        )

        return findings

    @staticmethod
    def _get_rds_tags(rds: object, arn: str) -> dict[str, str]:
        if not arn:
            return {}
        try:
            resp = rds.list_tags_for_resource(ResourceName=arn)  # type: ignore[attr-defined]
            return {t["Key"]: t["Value"] for t in resp.get("TagList", [])}
        except Exception:  # noqa: BLE001
            return {}
