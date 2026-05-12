"""Shared pytest fixtures for CloudThrift tests."""

from __future__ import annotations

import os

import boto3
import pytest
from moto import mock_aws

# Prevent any accidental real AWS calls
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test-key")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test-secret")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("CLOUDTHRIFT_DEMO_MODE", "false")


@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS credentials so moto can intercept calls."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def ec2_client(aws_credentials):
    with mock_aws():
        yield boto3.client("ec2", region_name="us-east-1")


@pytest.fixture(scope="function")
def s3_client(aws_credentials):
    with mock_aws():
        yield boto3.client("s3", region_name="us-east-1")


@pytest.fixture(scope="function")
def rds_client(aws_credentials):
    with mock_aws():
        yield boto3.client("rds", region_name="us-east-1")


@pytest.fixture(scope="function")
def clean_store():
    """Return a fresh StateStore for each test."""
    from cloudthrift.state import StateStore
    return StateStore()
