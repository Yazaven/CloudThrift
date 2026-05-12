"""AWS resource scanners package."""

from cloudthrift.scanners.ec2 import EC2Scanner
from cloudthrift.scanners.elb import ELBScanner
from cloudthrift.scanners.lambda_fn import LambdaScanner
from cloudthrift.scanners.rds import RDSScanner
from cloudthrift.scanners.s3 import S3Scanner
from cloudthrift.scanners.snapshots import SnapshotScanner

__all__ = [
    "EC2Scanner",
    "ELBScanner",
    "LambdaScanner",
    "RDSScanner",
    "S3Scanner",
    "SnapshotScanner",
]
