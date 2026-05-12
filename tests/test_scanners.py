"""Integration tests for AWS scanners using moto mocks."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

from cloudthrift.models import RemediationAction, ResourceType


@pytest.fixture(autouse=True)
def aws_env(aws_credentials):
    """Ensure credentials are set for every test in this module."""


# ── EC2 / EBS / EIP scanners ──────────────────────────────────────────────────


class TestEC2Scanner:
    @mock_aws
    def test_stopped_instance_detected(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")

        reservation = ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t3.medium",
            MinCount=1,
            MaxCount=1,
        )
        instance_id = reservation["Instances"][0]["InstanceId"]
        ec2.stop_instances(InstanceIds=[instance_id])

        # Patch the age threshold to 0 so moto's just-stopped instance is detected
        from unittest.mock import patch
        with patch("cloudthrift.scanners.ec2.settings") as mock_cfg:
            mock_cfg.stopped_instance_age_days = 0
            from cloudthrift.scanners.ec2 import EC2Scanner
            scanner = EC2Scanner("us-east-1")
            findings = scanner.scan()

        assert any(f.resource_id == instance_id for f in findings)
        finding = next(f for f in findings if f.resource_id == instance_id)
        assert finding.resource_type == ResourceType.EC2_INSTANCE
        assert finding.remediation_action == RemediationAction.TERMINATE_INSTANCE

    @mock_aws
    def test_running_instance_not_flagged(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        reservation = ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t3.small",
            MinCount=1,
            MaxCount=1,
        )
        instance_id = reservation["Instances"][0]["InstanceId"]

        from cloudthrift.scanners.ec2 import EC2Scanner
        scanner = EC2Scanner("us-east-1")
        findings = scanner.scan()

        assert not any(f.resource_id == instance_id for f in findings)


class TestEBSScanner:
    @mock_aws
    def test_unattached_volume_detected(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vol = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=100,
            VolumeType="gp2",
        )
        volume_id = vol["VolumeId"]

        # Patch threshold to 0 so a freshly-created unattached volume is detected
        from unittest.mock import patch
        with patch("cloudthrift.scanners.ec2.settings") as mock_cfg:
            mock_cfg.unattached_volume_age_days = 0
            mock_cfg.gp2_gb_monthly_cost = 0.10
            mock_cfg.gp3_gb_monthly_cost = 0.08
            mock_cfg.io1_gb_monthly_cost = 0.125
            from cloudthrift.scanners.ec2 import EBSScanner
            scanner = EBSScanner("us-east-1")
            findings = scanner.scan()

        assert any(f.resource_id == volume_id for f in findings)
        finding = next(f for f in findings if f.resource_id == volume_id)
        assert finding.resource_type == ResourceType.EBS_VOLUME
        assert finding.estimated_monthly_cost == pytest.approx(10.0, abs=0.01)

    @mock_aws
    def test_attached_volume_not_flagged(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        reservation = ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
        )
        instance_id = reservation["Instances"][0]["InstanceId"]
        vol = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=50,
            VolumeType="gp2",
        )
        volume_id = vol["VolumeId"]
        ec2.attach_volume(
            VolumeId=volume_id,
            InstanceId=instance_id,
            Device="/dev/xvdf",
        )

        from cloudthrift.scanners.ec2 import EBSScanner
        scanner = EBSScanner("us-east-1")
        findings = scanner.scan()

        assert not any(f.resource_id == volume_id for f in findings)


class TestElasticIPScanner:
    @mock_aws
    def test_unassociated_eip_detected(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        alloc = ec2.allocate_address(Domain="vpc")
        alloc_id = alloc["AllocationId"]

        from cloudthrift.scanners.ec2 import ElasticIPScanner
        scanner = ElasticIPScanner("us-east-1")
        findings = scanner.scan()

        assert any(f.resource_id == alloc_id for f in findings)
        finding = next(f for f in findings if f.resource_id == alloc_id)
        assert finding.resource_type == ResourceType.ELASTIC_IP
        assert finding.remediation_action == RemediationAction.RELEASE_EIP

    @mock_aws
    def test_associated_eip_not_flagged(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        alloc = ec2.allocate_address(Domain="vpc")
        alloc_id = alloc["AllocationId"]

        reservation = ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
        )
        instance_id = reservation["Instances"][0]["InstanceId"]
        ec2.associate_address(AllocationId=alloc_id, InstanceId=instance_id)

        from cloudthrift.scanners.ec2 import ElasticIPScanner
        scanner = ElasticIPScanner("us-east-1")
        findings = scanner.scan()

        assert not any(f.resource_id == alloc_id for f in findings)


# ── State store ───────────────────────────────────────────────────────────────


class TestStateStore:
    def test_upsert_and_retrieve(self, clean_store):
        from cloudthrift.models import Finding, RemediationAction, ResourceType, Severity
        f = Finding(
            resource_type=ResourceType.ELASTIC_IP,
            resource_id="eip-test",
            region="us-east-1",
            account_id="123456789012",
            severity=Severity.LOW,
            title="Test EIP",
            description="Test",
            recommendation="Release.",
            remediation_action=RemediationAction.RELEASE_EIP,
        )
        clean_store.upsert_findings([f])
        retrieved = clean_store.get_finding(f.id)
        assert retrieved is not None
        assert retrieved.resource_id == "eip-test"

    def test_filter_by_severity(self, clean_store):
        from cloudthrift.models import Finding, RemediationAction, ResourceType, Severity
        for sev, rid in [(Severity.CRITICAL, "r1"), (Severity.LOW, "r2"), (Severity.HIGH, "r3")]:
            clean_store.upsert_findings([
                Finding(
                    resource_type=ResourceType.EBS_VOLUME,
                    resource_id=rid,
                    region="us-east-1",
                    account_id="123456789012",
                    severity=sev,
                    title=f"Volume {rid}",
                    description="test",
                    recommendation="delete",
                    remediation_action=RemediationAction.DELETE_VOLUME,
                )
            ])
        critical_findings = clean_store.get_all_findings(severity="CRITICAL")
        assert len(critical_findings) == 1
        assert critical_findings[0].resource_id == "r1"

    def test_total_monthly_waste(self, clean_store):
        from cloudthrift.models import Finding, RemediationAction, ResourceType, Severity
        for cost in [100.0, 50.0, 25.0]:
            clean_store.upsert_findings([
                Finding(
                    resource_type=ResourceType.EC2_INSTANCE,
                    resource_id=f"i-{cost}",
                    region="us-east-1",
                    account_id="123456789012",
                    severity=Severity.HIGH,
                    title="Stopped instance",
                    description="test",
                    estimated_monthly_cost=cost,
                    recommendation="terminate",
                    remediation_action=RemediationAction.TERMINATE_INSTANCE,
                )
            ])
        assert clean_store.total_monthly_waste() == pytest.approx(175.0)

    def test_update_finding_status(self, clean_store):
        from cloudthrift.models import Finding, FindingStatus, RemediationAction, ResourceType, Severity
        f = Finding(
            resource_type=ResourceType.EBS_VOLUME,
            resource_id="vol-status-test",
            region="us-east-1",
            account_id="123456789012",
            severity=Severity.MEDIUM,
            title="Volume",
            description="test",
            recommendation="delete",
            remediation_action=RemediationAction.DELETE_VOLUME,
        )
        clean_store.upsert_findings([f])
        result = clean_store.update_finding_status(f.id, FindingStatus.SUPPRESSED)
        assert result is True
        updated = clean_store.get_finding(f.id)
        assert updated.status == FindingStatus.SUPPRESSED

    def test_update_nonexistent_finding(self, clean_store):
        from cloudthrift.models import FindingStatus
        result = clean_store.update_finding_status("NOPE", FindingStatus.SUPPRESSED)
        assert result is False
