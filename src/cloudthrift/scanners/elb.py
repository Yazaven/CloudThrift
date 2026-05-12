"""Elastic Load Balancer scanner — idle and target-less load balancers."""

from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudthrift.config import settings
from cloudthrift.models import Finding, RemediationAction, ResourceType, Severity
from cloudthrift.scanners.base import BaseScanner

_ALB_MONTHLY = 16.43   # ~$0.0225/LCU-hour base, minimum ~$16/mo
_NLB_MONTHLY = 16.43
_CLB_MONTHLY = 18.25


class ELBScanner(BaseScanner):
    """Detects Application, Network, and Classic load balancers with no traffic."""

    resource_type = ResourceType.ELB

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_v2())
        findings.extend(self._scan_classic())
        return findings

    def _scan_v2(self) -> list[Finding]:
        """ALB and NLB via elbv2 API."""
        elbv2 = self.client("elbv2")
        cw = self.client("cloudwatch")
        account = self.account_id
        findings: list[Finding] = []

        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                lb_arn = lb["LoadBalancerArn"]
                lb_name = lb.get("LoadBalancerName", "")
                lb_type = lb.get("Type", "application").lower()
                monthly = _ALB_MONTHLY if lb_type == "application" else _NLB_MONTHLY

                # ── Check for target groups with no healthy targets ────────
                has_healthy = self._has_healthy_targets(elbv2, lb_arn)
                if not has_healthy:
                    tags = self._get_elb_tags(elbv2, lb_arn)
                    findings.append(
                        Finding(
                            resource_type=ResourceType.ELB,
                            resource_id=lb_arn,
                            resource_name=lb_name,
                            resource_arn=lb_arn,
                            region=self.region,
                            account_id=account,
                            severity=Severity.from_monthly_cost(monthly),
                            title=f"Load balancer with no healthy targets: {lb_name}",
                            description=(
                                f"{lb_type.upper()} load balancer {lb_name} has no healthy targets "
                                f"registered across any of its target groups. Traffic will return "
                                f"5xx errors. The load balancer costs ~${monthly:,.2f}/mo regardless."
                            ),
                            estimated_monthly_cost=monthly,
                            tags=tags,
                            age_days=0,
                            recommendation=(
                                "Register healthy targets or delete the load balancer. "
                                "If this is a pre-production LB with intermittent use, "
                                "consider using a single shared ALB with host/path routing rules."
                            ),
                            remediation_action=RemediationAction.DELETE_ELB,
                            metadata={
                                "lb_type": lb_type,
                                "scheme": lb.get("Scheme", ""),
                                "state": lb.get("State", {}).get("Code", ""),
                                "dns_name": lb.get("DNSName", ""),
                            },
                        )
                    )
                    continue

                # ── Check for zero requests in the last N days ─────────────
                idle_days = self._days_since_requests(cw, lb_arn, lb_type)
                if idle_days is not None and idle_days > settings.idle_elb_days:
                    tags = self._get_elb_tags(elbv2, lb_arn)
                    findings.append(
                        Finding(
                            resource_type=ResourceType.ELB,
                            resource_id=lb_arn,
                            resource_name=lb_name,
                            resource_arn=lb_arn,
                            region=self.region,
                            account_id=account,
                            severity=Severity.MEDIUM,
                            title=f"Idle load balancer: {lb_name}",
                            description=(
                                f"{lb_type.upper()} load balancer {lb_name} has processed "
                                f"fewer than {settings.idle_elb_request_threshold} requests/day "
                                f"for the past {idle_days} days, costing ${monthly:,.2f}/mo."
                            ),
                            estimated_monthly_cost=monthly,
                            tags=tags,
                            age_days=idle_days,
                            recommendation=(
                                "Consolidate this load balancer onto a shared ALB using "
                                "host-based routing rules, or delete if no longer needed."
                            ),
                            remediation_action=RemediationAction.DELETE_ELB,
                            metadata={
                                "lb_type": lb_type,
                                "idle_days": idle_days,
                                "dns_name": lb.get("DNSName", ""),
                            },
                        )
                    )

        return findings

    def _scan_classic(self) -> list[Finding]:
        """Classic ELB (v1) via elb API."""
        elb = self.client("elb")
        account = self.account_id
        findings: list[Finding] = []

        try:
            paginator = elb.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancerDescriptions", []):
                    lb_name = lb["LoadBalancerName"]
                    instances = lb.get("Instances", [])
                    if not instances:
                        findings.append(
                            Finding(
                                resource_type=ResourceType.ELB,
                                resource_id=lb_name,
                                resource_name=lb_name,
                                resource_arn=f"arn:aws:elasticloadbalancing:{self.region}:{account}:loadbalancer/{lb_name}",
                                region=self.region,
                                account_id=account,
                                severity=Severity.MEDIUM,
                                title=f"Classic ELB with no instances: {lb_name}",
                                description=(
                                    f"Classic (v1) load balancer {lb_name} has no EC2 instances "
                                    f"registered. Classic ELBs should be migrated to ALB/NLB and "
                                    f"cost ~${_CLB_MONTHLY}/mo idle."
                                ),
                                estimated_monthly_cost=_CLB_MONTHLY,
                                age_days=0,
                                recommendation=(
                                    "Migrate to ALB (HTTP/HTTPS) or NLB (TCP/UDP) and decommission "
                                    "this Classic ELB. AWS is retiring Classic ELB features."
                                ),
                                remediation_action=RemediationAction.DELETE_ELB,
                                metadata={"lb_type": "classic", "dns_name": lb.get("DNSName", "")},
                            )
                        )
        except ClientError:
            pass

        return findings

    @staticmethod
    def _has_healthy_targets(elbv2: object, lb_arn: str) -> bool:
        try:
            tg_resp = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)  # type: ignore[attr-defined]
            tgs = tg_resp.get("TargetGroups", [])
            if not tgs:
                return False
            for tg in tgs:
                health = elbv2.describe_target_health(  # type: ignore[attr-defined]
                    TargetGroupArn=tg["TargetGroupArn"]
                )
                for th in health.get("TargetHealthDescriptions", []):
                    if th.get("TargetHealth", {}).get("State") == "healthy":
                        return True
        except ClientError:
            return True  # fail-open: don't flag if we can't determine
        return False

    @staticmethod
    def _get_elb_tags(elbv2: object, lb_arn: str) -> dict[str, str]:
        try:
            resp = elbv2.describe_tags(ResourceArns=[lb_arn])  # type: ignore[attr-defined]
            for desc in resp.get("TagDescriptions", []):
                return {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
        except ClientError:
            pass
        return {}

    @staticmethod
    def _days_since_requests(cw: object, lb_arn: str, lb_type: str) -> int | None:
        # Extract the load balancer name suffix used in CloudWatch metrics
        metric_name = "RequestCount" if lb_type == "application" else "ActiveFlowCount"
        lb_suffix = lb_arn.split("loadbalancer/")[-1]
        try:
            resp = cw.get_metric_statistics(  # type: ignore[attr-defined]
                Namespace="AWS/ApplicationELB" if lb_type == "application" else "AWS/NetworkELB",
                MetricName=metric_name,
                Dimensions=[{"Name": "LoadBalancer", "Value": lb_suffix}],
                StartTime=datetime(2000, 1, 1, tzinfo=timezone.utc),
                EndTime=datetime.now(timezone.utc),
                Period=86400,
                Statistics=["Sum"],
            )
            points = sorted(resp.get("Datapoints", []), key=lambda p: p["Timestamp"])
            for p in reversed(points):
                if p["Sum"] > settings.idle_elb_request_threshold:
                    last_ts = p["Timestamp"]
                    if last_ts.tzinfo is None:
                        last_ts = last_ts.replace(tzinfo=timezone.utc)
                    return (datetime.now(timezone.utc) - last_ts).days
        except ClientError:
            pass
        return None
