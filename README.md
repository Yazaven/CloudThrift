# CloudThrift

An MCP server that connects to your AWS account, finds idle and orphaned resources, estimates what they cost, and guides you through removing them safely.

Works with Claude Desktop and the `claude` CLI via the Model Context Protocol.

---
## Stack

Python 3.11+ · boto3 · MCP SDK · Pydantic v2 · Rich · pytest + moto

## What it scans

### Resource Scanners
Here is what CloudThrift actively detects and the AWS APIs it uses to find them under the hood:

*   **EC2:** Finds stopped instances (older than N days) using `describe_instances`.
*   **EBS:** Identifies unattached volumes using `describe_volumes`.
*   **Elastic IP:** Spots unassociated allocations using `describe_addresses`.
*   **S3:** Tracks down empty buckets and dormant storage using `list_buckets` and CloudWatch.
*   **RDS:** Locates stopped instances and single-AZ production DBs using `describe_db_instances`.
*   **ELB:** Flags idle ALB/NLB/CLBs or those with no healthy targets using `describe_load_balancers` and CloudWatch.
*   **Lambda:** Detects functions with zero invocations using `list_functions` and CloudWatch.
*   **Snapshots:** Finds aging EBS snapshots and orphaned AMIs using `describe_snapshots` and `describe_images`.Each finding includes severity, estimated monthly cost, and a recommended action.

---

## AWS usage

```bash
# Named profile
AWS_PROFILE=my-profile cloudthrift

# Multiple regions
cloudthrift --region us-east-1 --region eu-west-1

# Via environment variable
CLOUDTHRIFT_AWS_REGIONS='["us-east-1","eu-west-1"]' cloudthrift
```

---

## Claude Desktop / CLI setup

Edit `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or  
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "cloudthrift": {
      "command": "cloudthrift",
      "args": [],
      "env": {
        "CLOUDTHRIFT_DEMO_MODE": "true"
      }
    }
  }
}
```

Remove `CLOUDTHRIFT_DEMO_MODE` and add `AWS_PROFILE` to scan a real account. Restart Claude Desktop after changing the config.

---

## IAM permissions

All scanners are read-only (`describe*`, `list*`, `get*`):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:Describe*",
      "elasticloadbalancing:Describe*",
      "rds:Describe*",
      "rds:ListTagsForResource",
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "lambda:ListFunctions",
      "lambda:ListTags",
      "cloudwatch:GetMetricStatistics",
      "ce:GetCostAndUsage",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

For remediation execution add the relevant write permissions (`ec2:DeleteVolume`, `ec2:ReleaseAddress`, `ec2:TerminateInstances`, etc.) scoped as tightly as you need.

---

## Remediation pipeline

Nothing is deleted without an explicit confirmation step.

1. `scan_resources` — produces findings
2. `create_remediation_plan` — dry-run by default; shows exactly what would happen and flags destructive steps
3. `approve_remediation_plan` — must be called with your name before any destructive action executes
4. `execute_remediation_plan` — runs each step in order, logs every outcome

The in-memory audit log records every action (including dry-runs) and is readable via `get_audit_log`.

---

## MCP interface

**Tools:** `scan_resources`, `get_findings`, `analyze_costs`, `generate_waste_report`, `create_remediation_plan`, `approve_remediation_plan`, `execute_remediation_plan`, `get_resource_details`, `suppress_finding`, `get_audit_log`

**Resources:** `cloudthrift://findings/all`, `cloudthrift://report/latest`, `cloudthrift://audit-log`, `cloudthrift://config`

**Prompts:** `finops_advisor` (full scan-to-remediation session), `remediation_guide` (step-by-step with per-resource confirmation), `weekly_finops_report`

---

## Configuration

```env
CLOUDTHRIFT_AWS_REGIONS=["us-east-1","us-west-2"]
CLOUDTHRIFT_STOPPED_INSTANCE_AGE_DAYS=7
CLOUDTHRIFT_UNATTACHED_VOLUME_AGE_DAYS=3
CLOUDTHRIFT_OLD_SNAPSHOT_DAYS=90
CLOUDTHRIFT_UNUSED_LAMBDA_DAYS=30
CLOUDTHRIFT_IDLE_ELB_REQUEST_THRESHOLD=100
CLOUDTHRIFT_IDLE_ELB_DAYS=14
CLOUDTHRIFT_REQUIRE_APPROVAL_FOR_DESTRUCTIVE=true
CLOUDTHRIFT_DEMO_MODE=false
```

---

## Known limitations

**S3 dormant detection** — uses the `PutRequests` CloudWatch metric with `FilterId=EntireBucket`, which only exists if you've enabled S3 Request Metrics on the bucket with that filter name. Most accounts don't have this; the check falls back gracefully to `None` and dormant (non-empty) buckets are skipped. Empty buckets work without any setup.

**EC2 stop time** — derived from the `StateTransitionReason` string (`User initiated (YYYY-MM-DD HH:MM:SS GMT)`). If the format doesn't match (e.g., API-initiated stop, maintenance), the instance is treated as just stopped and won't be flagged until enough time has passed for a future scan to pick it up.

**EBS detachment time** — AWS has no API for when a volume was detached. Age shown is the volume's creation date, not time-since-detachment.

**AMIs in Auto Scaling Groups** — the scanner checks instances and launch templates. AMIs referenced only by an ASG's launch configuration (not launch template) could be flagged as unused. Check before deleting.

**In-memory state** — findings, plans, and the audit log are cleared on process restart.

---
