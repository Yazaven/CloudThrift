"""EC2 instance, EBS volume, and Elastic IP scanners."""

from __future__ import annotations

from datetime import datetime, timezone

from cloudthrift.config import settings
from cloudthrift.models import Finding, RemediationAction, ResourceType, Severity
from cloudthrift.scanners.base import BaseScanner

# Monthly on-demand pricing approximations (USD) for common instance families.
#  deployments should use
#  AWS Pricing API or Cost Explorer.
_EC2_HOURLY: dict[str, float] = {
    "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
    "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384,
    "m5.4xlarge": 0.768, "m5.8xlarge": 1.536, "m5.12xlarge": 2.304,
    "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34,
    "r5.large": 0.126, "r5.xlarge": 0.252, "r5.2xlarge": 0.504,
    "p3.2xlarge": 3.06, "p3.8xlarge": 12.24,
}

_EBS_GB_MONTHLY: dict[str, float] = {
    "gp2": settings.gp2_gb_monthly_cost,
    "gp3": settings.gp3_gb_monthly_cost,
    "io1": settings.io1_gb_monthly_cost,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.025,
    "standard": 0.05,
}


def _age_days(dt: datetime) -> int:
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (now - dt).days)


class EC2Scanner(BaseScanner):
    """Finds EC2 instances that have been stopped for too long."""

    resource_type = ResourceType.EC2_INSTANCE

    def scan(self) -> list[Finding]:
        ec2 = self.client("ec2")
        account = self.account_id
        findings: list[Finding] = []

        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    state_reason = inst.get("StateTransitionReason", "")
                    stopped_time = self._parse_stop_time(state_reason, inst.get("LaunchTime"))
                    age = _age_days(stopped_time)

                    if age < settings.stopped_instance_age_days:
                        continue

                    itype = inst.get("InstanceType", "unknown")
                    hourly = _EC2_HOURLY.get(itype, 0.096)
                    # Stopped instances still incur EBS costs, not compute.
                    # We flag the compute waste as the opportunity cost of Reserved Instance.
                    monthly_cost = hourly * 24 * 30

                    tags = self.tags_to_dict(inst.get("Tags"))
                    name = tags.get("Name", inst["InstanceId"])

                    findings.append(
                        Finding(
                            resource_type=ResourceType.EC2_INSTANCE,
                            resource_id=inst["InstanceId"],
                            resource_name=name,
                            resource_arn=f"arn:aws:ec2:{self.region}:{account}:instance/{inst['InstanceId']}",
                            region=self.region,
                            account_id=account,
                            severity=Severity.from_monthly_cost(monthly_cost),
                            title=f"Stopped EC2 instance: {name}",
                            description=(
                                f"Instance {inst['InstanceId']} ({itype}) has been stopped for "
                                f"{age} days. Stopped instances still incur EBS storage costs "
                                f"and block EC2 capacity. Opportunity cost: ${monthly_cost:,.2f}/mo."
                            ),
                            estimated_monthly_cost=monthly_cost,
                            tags=tags,
                            age_days=age,
                            recommendation=(
                                "Terminate the instance if unused, or start it if needed. "
                                "Consider creating an AMI snapshot first for safe termination."
                            ),
                            remediation_action=RemediationAction.TERMINATE_INSTANCE,
                            metadata={
                                "instance_type": itype,
                                "platform": inst.get("Platform", "linux"),
                                "launch_time": inst.get("LaunchTime", "").isoformat()
                                if hasattr(inst.get("LaunchTime", ""), "isoformat")
                                else str(inst.get("LaunchTime", "")),
                                "stopped_reason": state_reason,
                                "vpc_id": inst.get("VpcId", ""),
                                "subnet_id": inst.get("SubnetId", ""),
                            },
                        )
                    )

        return findings

    @staticmethod
    def _parse_stop_time(reason: str, fallback: datetime | None) -> datetime:
        """Extract the stop timestamp from the StateTransitionReason string."""
        # Format: "User initiated (2024-01-15 14:32:06 GMT)"
        if "(" in reason and ")" in reason:
            try:
                ts_str = reason.split("(")[1].rstrip(")")
                return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S GMT").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                pass
        # Can't determine stop time — treat as just stopped to avoid false positives.
        return datetime.now(timezone.utc)


class EBSScanner(BaseScanner):
    """Finds unattached EBS volumes wasting storage spend."""

    resource_type = ResourceType.EBS_VOLUME

    def scan(self) -> list[Finding]:
        ec2 = self.client("ec2")
        account = self.account_id
        findings: list[Finding] = []

        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(
            Filters=[{"Name": "status", "Values": ["available"]}]
        ):
            for vol in page["Volumes"]:
                age = _age_days(vol["CreateTime"])
                if age < settings.unattached_volume_age_days:
                    continue

                vol_type = vol.get("VolumeType", "gp2")
                size_gb = vol.get("Size", 0)
                per_gb = _EBS_GB_MONTHLY.get(vol_type, 0.10)
                monthly_cost = size_gb * per_gb

                tags = self.tags_to_dict(vol.get("Tags"))
                name = tags.get("Name", vol["VolumeId"])

                findings.append(
                    Finding(
                        resource_type=ResourceType.EBS_VOLUME,
                        resource_id=vol["VolumeId"],
                        resource_name=name,
                        resource_arn=f"arn:aws:ec2:{self.region}:{account}:volume/{vol['VolumeId']}",
                        region=self.region,
                        account_id=account,
                        severity=Severity.from_monthly_cost(monthly_cost),
                        title=f"Unattached EBS volume: {name}",
                        description=(
                            f"EBS volume {vol['VolumeId']} ({size_gb} GiB {vol_type.upper()}) "
                            f"is unattached and was created {age} days ago, accruing "
                            f"${monthly_cost:,.2f}/mo in storage charges with zero utilisation."
                        ),
                        estimated_monthly_cost=monthly_cost,
                        tags=tags,
                        age_days=age,
                        recommendation=(
                            "Create a final snapshot for data retention, then delete the volume. "
                            "If data is needed, attach it to an EC2 instance first."
                        ),
                        remediation_action=RemediationAction.DELETE_VOLUME,
                        metadata={
                            "volume_type": vol_type,
                            "size_gb": size_gb,
                            "iops": vol.get("Iops"),
                            "throughput": vol.get("Throughput"),
                            "encrypted": vol.get("Encrypted", False),
                            "availability_zone": vol.get("AvailabilityZone", ""),
                        },
                    )
                )

        return findings


class ElasticIPScanner(BaseScanner):
    """Finds allocated Elastic IPs not associated with any resource."""

    resource_type = ResourceType.ELASTIC_IP

    def scan(self) -> list[Finding]:
        ec2 = self.client("ec2")
        account = self.account_id
        findings: list[Finding] = []

        response = ec2.describe_addresses()
        for addr in response.get("Addresses", []):
            # Only flag EIPs that are allocated but unassociated
            if addr.get("AssociationId"):
                continue

            tags = self.tags_to_dict(addr.get("Tags"))
            name = tags.get("Name", addr.get("PublicIp", "unknown"))
            monthly_cost = settings.eip_monthly_cost

            findings.append(
                Finding(
                    resource_type=ResourceType.ELASTIC_IP,
                    resource_id=addr.get("AllocationId", addr.get("PublicIp", "")),
                    resource_name=name,
                    resource_arn=(
                        f"arn:aws:ec2:{self.region}:{account}:elastic-ip/"
                        f"{addr.get('AllocationId', '')}"
                    ),
                    region=self.region,
                    account_id=account,
                    severity=Severity.LOW,
                    title=f"Unattached Elastic IP: {addr.get('PublicIp')}",
                    description=(
                        f"Elastic IP {addr.get('PublicIp')} (allocation {addr.get('AllocationId')}) "
                        f"is allocated but not associated with any instance or network interface. "
                        f"AWS charges ${monthly_cost:.2f}/mo for idle EIPs."
                    ),
                    estimated_monthly_cost=monthly_cost,
                    tags=tags,
                    age_days=0,
                    recommendation=(
                        "Release the Elastic IP if no longer needed, or associate it with a running "
                        "instance. Holding an idle EIP costs $0.005/hr (~$3.65/mo)."
                    ),
                    remediation_action=RemediationAction.RELEASE_EIP,
                    metadata={
                        "public_ip": addr.get("PublicIp", ""),
                        "allocation_id": addr.get("AllocationId", ""),
                        "domain": addr.get("Domain", "vpc"),
                    },
                )
            )

        return findings
