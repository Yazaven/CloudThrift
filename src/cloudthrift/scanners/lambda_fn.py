"""Lambda function scanner — unused functions and old versions."""

from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudthrift.config import settings
from cloudthrift.models import Finding, RemediationAction, ResourceType, Severity
from cloudthrift.scanners.base import BaseScanner

# Lambda compute cost is effectively zero for dormant functions.
# The waste here is operational: dead code, stale IAM roles, security surface.
_LAMBDA_MONTHLY_ESTIMATE = 0.0  # compute cost
_LAMBDA_RISK_COST = 5.0         # notional cost for security/hygiene risk


class LambdaScanner(BaseScanner):
    """Detects Lambda functions with no recent invocations."""

    resource_type = ResourceType.LAMBDA_FUNCTION

    def scan(self) -> list[Finding]:
        lambda_client = self.client("lambda")
        cw = self.client("cloudwatch")
        account = self.account_id
        findings: list[Finding] = []

        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                fn_name = fn["FunctionName"]
                fn_arn = fn["FunctionArn"]
                runtime = fn.get("Runtime", "unknown")
                modified = fn.get("LastModified", "")

                invocation_days = self._days_since_invocation(cw, fn_name)
                if invocation_days is None:
                    continue
                if invocation_days < settings.unused_lambda_days:
                    continue

                # If no CloudWatch data exists (invocation_days==365 sentinel) but
                # the function was modified recently, it's new — don't flag it.
                if invocation_days == 365 and modified:
                    try:
                        from datetime import timedelta
                        from dateutil import parser as dtparser
                        mod_dt = dtparser.parse(modified)
                        if mod_dt.tzinfo is None:
                            mod_dt = mod_dt.replace(tzinfo=timezone.utc)
                        if (datetime.now(timezone.utc) - mod_dt).days < settings.unused_lambda_days:
                            continue
                    except (ValueError, ImportError):
                        pass

                error_rate = self._recent_error_rate(cw, fn_name)
                tags = self._get_lambda_tags(lambda_client, fn_arn)

                severity = Severity.INFO
                description_suffix = ""

                if error_rate is not None and error_rate > 0.5:
                    severity = Severity.HIGH
                    description_suffix = (
                        f" The function also has a {error_rate:.0%} error rate on recent "
                        f"invocations — investigate before any remediation."
                    )

                findings.append(
                    Finding(
                        resource_type=ResourceType.LAMBDA_FUNCTION,
                        resource_id=fn_name,
                        resource_name=fn_name,
                        resource_arn=fn_arn,
                        region=self.region,
                        account_id=account,
                        severity=severity,
                        title=f"Unused Lambda function: {fn_name}",
                        description=(
                            f"Lambda function {fn_name} ({runtime}) has had no invocations "
                            f"in the last {invocation_days} days. Last code modification: "
                            f"{modified[:10] if modified else 'unknown'}. Unused functions "
                            f"expand the IAM attack surface and add cognitive overhead."
                            + description_suffix
                        ),
                        estimated_monthly_cost=_LAMBDA_RISK_COST,
                        tags=tags,
                        age_days=invocation_days,
                        recommendation=(
                            "Delete unused Lambda functions to reduce IAM attack surface. "
                            "Check CloudWatch Logs for the last invocation before deleting. "
                            "Archive the code in version control first."
                        ),
                        remediation_action=RemediationAction.DELETE_FUNCTION,
                        metadata={
                            "runtime": runtime,
                            "memory_mb": fn.get("MemorySize", 128),
                            "timeout_seconds": fn.get("Timeout", 3),
                            "handler": fn.get("Handler", ""),
                            "last_modified": modified,
                            "days_since_invocation": invocation_days,
                            "error_rate": error_rate,
                        },
                    )
                )

        return findings

    @staticmethod
    def _days_since_invocation(cw: object, fn_name: str) -> int | None:
        try:
            resp = cw.get_metric_statistics(  # type: ignore[attr-defined]
                Namespace="AWS/Lambda",
                MetricName="Invocations",
                Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
                StartTime=datetime(2000, 1, 1, tzinfo=timezone.utc),
                EndTime=datetime.now(timezone.utc),
                Period=86400,
                Statistics=["Sum"],
            )
            points = sorted(resp.get("Datapoints", []), key=lambda p: p["Timestamp"])
            for p in reversed(points):
                if p["Sum"] > 0:
                    last_ts = p["Timestamp"]
                    if last_ts.tzinfo is None:
                        last_ts = last_ts.replace(tzinfo=timezone.utc)
                    return (datetime.now(timezone.utc) - last_ts).days
            # No data points at all — function has never been invoked (or data expired)
            return 365
        except ClientError:
            return None

    @staticmethod
    def _recent_error_rate(cw: object, fn_name: str) -> float | None:
        """Return error rate (0–1) over the last 30 days, or None if unavailable."""
        from datetime import timedelta

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=30)
        try:
            inv = cw.get_metric_statistics(  # type: ignore[attr-defined]
                Namespace="AWS/Lambda",
                MetricName="Invocations",
                Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
                StartTime=start,
                EndTime=end,
                Period=2592000,
                Statistics=["Sum"],
            )
            err = cw.get_metric_statistics(  # type: ignore[attr-defined]
                Namespace="AWS/Lambda",
                MetricName="Errors",
                Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
                StartTime=start,
                EndTime=end,
                Period=2592000,
                Statistics=["Sum"],
            )
            inv_sum = sum(p["Sum"] for p in inv.get("Datapoints", []))
            err_sum = sum(p["Sum"] for p in err.get("Datapoints", []))
            if inv_sum > 0:
                return err_sum / inv_sum
        except ClientError:
            pass
        return None

    @staticmethod
    def _get_lambda_tags(lambda_client: object, fn_arn: str) -> dict[str, str]:
        try:
            resp = lambda_client.list_tags(Resource=fn_arn)  # type: ignore[attr-defined]
            return resp.get("Tags", {})
        except ClientError:
            return {}
