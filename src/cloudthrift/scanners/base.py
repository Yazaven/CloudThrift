"""Abstract base class shared by all resource scanners."""

from __future__ import annotations

import abc
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from cloudthrift.config import settings
from cloudthrift.models import Finding, ResourceType

logger = logging.getLogger(__name__)


class BaseScanner(abc.ABC):
    """Provides a boto3 session factory and a uniform scan interface."""

    resource_type: ResourceType  # subclasses must declare this

    def __init__(self, region: str) -> None:
        self.region = region
        self._session = self._build_session()
        self._account_id: str | None = None

    @staticmethod
    def build_session(region: str) -> boto3.Session:
        """Build a boto3 session honouring aws_profile and aws_role_arn from config."""
        kwargs: dict[str, Any] = {"region_name": region}
        if settings.aws_profile:
            kwargs["profile_name"] = settings.aws_profile
        session = boto3.Session(**kwargs)

        if settings.aws_role_arn:
            sts = session.client("sts")
            creds = sts.assume_role(
                RoleArn=settings.aws_role_arn,
                RoleSessionName="cloudthrift-scan",
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        return session

    def _build_session(self) -> boto3.Session:
        return self.build_session(self.region)

    def client(self, service: str) -> Any:
        return self._session.client(service)

    @property
    def account_id(self) -> str:
        if self._account_id is None:
            try:
                self._account_id = self.client("sts").get_caller_identity()["Account"]
            except (ClientError, NoCredentialsError):
                self._account_id = "unknown"
        return self._account_id

    @abc.abstractmethod
    def scan(self) -> list[Finding]:
        """Return findings for this scanner's resource type in self.region."""

    def safe_scan(self) -> tuple[list[Finding], list[str]]:
        """Wraps scan() and captures any AWS errors as non-fatal strings."""
        try:
            findings = self.scan()
            return findings, []
        except NoCredentialsError:
            msg = f"[{self.resource_type.label}] No AWS credentials found — skipping {self.region}"
            logger.warning(msg)
            return [], [msg]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = f"[{self.resource_type.label}] AWS error in {self.region}: {code} — {exc}"
            logger.warning(msg)
            return [], [msg]
        except Exception as exc:  # noqa: BLE001
            msg = f"[{self.resource_type.label}] Unexpected error in {self.region}: {exc}"
            logger.exception(msg)
            return [], [msg]

    @staticmethod
    def extract_name(tags: list[dict[str, str]] | None, fallback: str = "") -> str:
        for tag in tags or []:
            if tag.get("Key") == "Name":
                return tag["Value"]
        return fallback

    @staticmethod
    def tags_to_dict(tags: list[dict[str, str]] | None) -> dict[str, str]:
        return {t["Key"]: t["Value"] for t in (tags or [])}
