"""EBS snapshot and AMI scanner — stale backups and orphaned images."""

from __future__ import annotations

from datetime import datetime, timezone

from cloudthrift.config import settings
from cloudthrift.models import Finding, RemediationAction, ResourceType, Severity
from cloudthrift.scanners.base import BaseScanner

_SNAPSHOT_GB_MONTHLY = 0.05   # EBS snapshot storage $/GiB/month


def _age_days(dt: datetime) -> int:
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (now - dt).days)


class SnapshotScanner(BaseScanner):
    """Finds old EBS snapshots and AMIs no longer backing running instances."""

    resource_type = ResourceType.EBS_SNAPSHOT

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        account = self.account_id

        findings.extend(self._scan_snapshots(account))
        findings.extend(self._scan_amis(account))
        return findings

    def _scan_snapshots(self, account: str) -> list[Finding]:
        ec2 = self.client("ec2")
        findings: list[Finding] = []

        # Build a set of snapshot IDs currently backing registered AMIs
        ami_snapshots = self._get_ami_snapshot_ids(ec2, account)

        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=[account]):
            for snap in page["Snapshots"]:
                snap_id = snap["SnapshotId"]
                age = _age_days(snap["StartTime"])

                if age < settings.old_snapshot_days:
                    continue

                # Skip snapshots that are backing a registered AMI
                if snap_id in ami_snapshots:
                    continue

                size_gb = snap.get("VolumeSize", 0)
                monthly_cost = size_gb * _SNAPSHOT_GB_MONTHLY
                tags = self.tags_to_dict(snap.get("Tags"))
                name = tags.get("Name", snap_id)

                findings.append(
                    Finding(
                        resource_type=ResourceType.EBS_SNAPSHOT,
                        resource_id=snap_id,
                        resource_name=name,
                        resource_arn=f"arn:aws:ec2:{self.region}:{account}:snapshot/{snap_id}",
                        region=self.region,
                        account_id=account,
                        severity=Severity.from_monthly_cost(monthly_cost),
                        title=f"Old EBS snapshot: {name}",
                        description=(
                            f"EBS snapshot {snap_id} ({size_gb} GiB) is {age} days old, "
                            f"not referenced by any AMI, and costs ${monthly_cost:,.2f}/mo "
                            f"in snapshot storage. Volume: {snap.get('VolumeId', 'n/a')}."
                        ),
                        estimated_monthly_cost=monthly_cost,
                        tags=tags,
                        age_days=age,
                        recommendation=(
                            "Apply a Data Lifecycle Manager (DLM) policy to automate snapshot "
                            "retention. Manually delete snapshots older than your RPO requirement."
                        ),
                        remediation_action=RemediationAction.DELETE_SNAPSHOT,
                        metadata={
                            "volume_id": snap.get("VolumeId", ""),
                            "size_gb": size_gb,
                            "description": snap.get("Description", ""),
                            "encrypted": snap.get("Encrypted", False),
                        },
                    )
                )

        return findings

    def _scan_amis(self, account: str) -> list[Finding]:
        """Find AMIs not in use by any running/stopped instance."""
        ec2 = self.client("ec2")
        findings: list[Finding] = []

        in_use = self._get_in_use_ami_ids(ec2)

        images_resp = ec2.describe_images(Owners=[account])
        for img in images_resp.get("Images", []):
            ami_id = img["ImageId"]
            if ami_id in in_use:
                continue

            creation_date_str = img.get("CreationDate", "")
            try:
                creation_dt = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                continue

            age = _age_days(creation_dt)
            if age < settings.old_snapshot_days:
                continue

            tags = self.tags_to_dict(img.get("Tags"))
            name = img.get("Name", ami_id)

            # Estimate monthly cost from backing snapshot sizes
            snap_size_gb = sum(
                bdm.get("Ebs", {}).get("VolumeSize", 0)
                for bdm in img.get("BlockDeviceMappings", [])
                if "Ebs" in bdm
            )
            monthly_cost = snap_size_gb * _SNAPSHOT_GB_MONTHLY

            findings.append(
                Finding(
                    resource_type=ResourceType.AMI,
                    resource_id=ami_id,
                    resource_name=name,
                    resource_arn=f"arn:aws:ec2:{self.region}:{account}:image/{ami_id}",
                    region=self.region,
                    account_id=account,
                    severity=Severity.from_monthly_cost(monthly_cost),
                    title=f"Unused AMI: {name}",
                    description=(
                        f"AMI {ami_id} ({name}) is {age} days old and not used by any "
                        f"EC2 instance. Its backing snapshots cost ~${monthly_cost:,.2f}/mo."
                    ),
                    estimated_monthly_cost=monthly_cost,
                    tags=tags,
                    age_days=age,
                    recommendation=(
                        "Deregister the AMI and delete its backing EBS snapshots. "
                        "Retain AMIs used in launch templates or Auto Scaling groups."
                    ),
                    remediation_action=RemediationAction.DEREGISTER_AMI,
                    metadata={
                        "architecture": img.get("Architecture", ""),
                        "platform": img.get("Platform", "linux"),
                        "virtualization_type": img.get("VirtualizationType", ""),
                        "backing_snapshot_size_gb": snap_size_gb,
                        "creation_date": creation_date_str,
                    },
                )
            )

        return findings

    @staticmethod
    def _get_ami_snapshot_ids(ec2: object, account: str) -> set[str]:
        snap_ids: set[str] = set()
        images_resp = ec2.describe_images(Owners=[account])  # type: ignore[attr-defined]
        for img in images_resp.get("Images", []):
            for bdm in img.get("BlockDeviceMappings", []):
                sid = bdm.get("Ebs", {}).get("SnapshotId")
                if sid:
                    snap_ids.add(sid)
        return snap_ids

    @staticmethod
    def _get_in_use_ami_ids(ec2: object) -> set[str]:
        in_use: set[str] = set()

        # Instances (running and stopped)
        paginator = ec2.get_paginator("describe_instances")  # type: ignore[attr-defined]
        for page in paginator.paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    ami = inst.get("ImageId")
                    if ami:
                        in_use.add(ami)

        # Launch Templates — must enumerate templates first, then fetch versions per template.
        # describe_launch_template_versions requires LaunchTemplateId when Versions is specified.
        try:
            lt_paginator = ec2.get_paginator("describe_launch_templates")  # type: ignore[attr-defined]
            for lt_page in lt_paginator.paginate():
                for lt in lt_page.get("LaunchTemplates", []):
                    lt_id = lt["LaunchTemplateId"]
                    try:
                        ver_resp = ec2.describe_launch_template_versions(  # type: ignore[attr-defined]
                            LaunchTemplateId=lt_id,
                            Versions=["$Latest"],
                        )
                        for ver in ver_resp.get("LaunchTemplateVersions", []):
                            ami = ver.get("LaunchTemplateData", {}).get("ImageId")
                            if ami:
                                in_use.add(ami)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass

        return in_use
