"""S3 bucket scanner — empty buckets and dormant storage."""

from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudthrift.config import settings
from cloudthrift.models import Finding, RemediationAction, ResourceType, Severity
from cloudthrift.scanners.base import BaseScanner

_S3_GB_MONTHLY = 0.023  # Standard storage $/GB/month


class S3Scanner(BaseScanner):
    """Detects empty S3 buckets and buckets with no write activity."""

    resource_type = ResourceType.S3_BUCKET

    def scan(self) -> list[Finding]:
        s3 = self.client("s3")
        cw = self.client("cloudwatch")
        account = self.account_id
        findings: list[Finding] = []

        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            name = bucket["Name"]

            # Filter to buckets in the target region
            try:
                loc = s3.get_bucket_location(Bucket=name)
                bucket_region = loc.get("LocationConstraint") or "us-east-1"
            except ClientError:
                continue

            if bucket_region != self.region:
                continue

            # ── Check object count and size via CloudWatch storage metrics ──
            size_bytes = self._get_bucket_size(cw, name)
            object_count = self._get_object_count(cw, name)
            monthly_cost = (size_bytes / (1024**3)) * _S3_GB_MONTHLY

            # ── Empty bucket ──────────────────────────────────────────────
            if object_count == 0:
                age = self._bucket_age_days(bucket.get("CreationDate"))
                if age < 1:
                    continue  # brand new — skip
                findings.append(
                    Finding(
                        resource_type=ResourceType.S3_BUCKET,
                        resource_id=name,
                        resource_name=name,
                        resource_arn=f"arn:aws:s3:::{name}",
                        region=self.region,
                        account_id=account,
                        severity=Severity.INFO,
                        title=f"Empty S3 bucket: {name}",
                        description=(
                            f"Bucket s3://{name} contains 0 objects and has no storage costs, "
                            f"but represents a namespace reservation and may have misconfigured "
                            f"policies, replication, or lifecycle rules still active."
                        ),
                        estimated_monthly_cost=0.0,
                        age_days=age,
                        recommendation=(
                            "Delete empty buckets that are no longer in use. "
                            "Verify there are no active notification, replication, or logging rules."
                        ),
                        remediation_action=RemediationAction.DELETE_BUCKET,
                        metadata={"object_count": 0, "size_bytes": 0},
                    )
                )
                continue

            # ── Dormant bucket (no recent PUTs) ──────────────────────────
            last_put_days = self._days_since_last_put(cw, name)
            if last_put_days is not None and last_put_days > settings.s3_inactive_days:
                findings.append(
                    Finding(
                        resource_type=ResourceType.S3_BUCKET,
                        resource_id=name,
                        resource_name=name,
                        resource_arn=f"arn:aws:s3:::{name}",
                        region=self.region,
                        account_id=account,
                        severity=Severity.from_monthly_cost(monthly_cost),
                        title=f"Dormant S3 bucket: {name}",
                        description=(
                            f"Bucket s3://{name} has not received a PUT request in "
                            f"{last_put_days} days. It contains {object_count:,} objects "
                            f"({size_bytes / (1024**3):.1f} GiB) costing ~${monthly_cost:,.2f}/mo."
                        ),
                        estimated_monthly_cost=monthly_cost,
                        age_days=last_put_days,
                        recommendation=(
                            "Apply an S3 Lifecycle rule to transition objects to "
                            "S3 Glacier Instant Retrieval (68% cheaper) or Glacier Deep Archive "
                            "(95% cheaper) for archival. Delete bucket if data is obsolete."
                        ),
                        remediation_action=RemediationAction.TAG_FOR_REVIEW,
                        metadata={
                            "object_count": object_count,
                            "size_bytes": size_bytes,
                            "size_gib": round(size_bytes / (1024**3), 2),
                            "days_since_last_put": last_put_days,
                        },
                    )
                )

        return findings

    def _get_bucket_size(self, cw: object, bucket_name: str) -> float:
        try:
            resp = cw.get_metric_statistics(  # type: ignore[attr-defined]
                Namespace="AWS/S3",
                MetricName="BucketSizeBytes",
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket_name},
                    {"Name": "StorageType", "Value": "StandardStorage"},
                ],
                StartTime=datetime(2000, 1, 1, tzinfo=timezone.utc),
                EndTime=datetime.now(timezone.utc),
                Period=86400,
                Statistics=["Average"],
            )
            points = resp.get("Datapoints", [])
            if points:
                return max(p["Average"] for p in points)
        except ClientError:
            pass
        return 0.0

    def _get_object_count(self, cw: object, bucket_name: str) -> int:
        try:
            resp = cw.get_metric_statistics(  # type: ignore[attr-defined]
                Namespace="AWS/S3",
                MetricName="NumberOfObjects",
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket_name},
                    {"Name": "StorageType", "Value": "AllStorageTypes"},
                ],
                StartTime=datetime(2000, 1, 1, tzinfo=timezone.utc),
                EndTime=datetime.now(timezone.utc),
                Period=86400,
                Statistics=["Average"],
            )
            points = resp.get("Datapoints", [])
            if points:
                return int(max(p["Average"] for p in points))
        except ClientError:
            pass
        return -1  # -1 = unable to determine

    def _days_since_last_put(self, cw: object, bucket_name: str) -> int | None:
        try:
            resp = cw.get_metric_statistics(  # type: ignore[attr-defined]
                Namespace="AWS/S3",
                MetricName="PutRequests",
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket_name},
                    {"Name": "FilterId", "Value": "EntireBucket"},
                ],
                StartTime=datetime(2000, 1, 1, tzinfo=timezone.utc),
                EndTime=datetime.now(timezone.utc),
                Period=86400,
                Statistics=["Sum"],
            )
            points = sorted(resp.get("Datapoints", []), key=lambda p: p["Timestamp"])
            if points:
                last_put = points[-1]["Timestamp"]
                if last_put.tzinfo is None:
                    last_put = last_put.replace(tzinfo=timezone.utc)
                return (datetime.now(timezone.utc) - last_put).days
        except ClientError:
            pass
        return None

    @staticmethod
    def _bucket_age_days(creation_date: datetime | None) -> int:
        if not creation_date:
            return 0
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - creation_date).days
