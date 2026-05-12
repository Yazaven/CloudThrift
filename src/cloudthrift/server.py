"""CloudThrift MCP Server â€” entry point and tool/resource/prompt definitions.

Transport: stdio (compatible with Claude Desktop, claude CLI, and any MCP client).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

import boto3
import click
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    EmbeddedResource,
    GetPromptResult,
    ImageContent,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
)
from pydantic import AnyUrl

from cloudthrift import config as _config
from cloudthrift.cost.analyzer import CostAnalyzer
from cloudthrift.demo import generate_demo_findings
from cloudthrift.models import (
    FindingStatus,
    RemediationPlan,
    ResourceType,
    ScanResult,
    Severity,
)
from cloudthrift.remediation.pipeline import RemediationPipeline
from cloudthrift.scanners import (
    EC2Scanner,
    ELBScanner,
    LambdaScanner,
    RDSScanner,
    S3Scanner,
    SnapshotScanner,
)
from cloudthrift.scanners.ec2 import EBSScanner, ElasticIPScanner
from cloudthrift.state import store
from cloudthrift.visualization.renderer import (
    render_cost_analysis,
    render_demo_banner,
    render_findings_table,
    render_remediation_plan,
    render_scan_summary,
    render_waste_report_markdown,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s â€” %(message)s")
logger = logging.getLogger(__name__)

app = Server("cloudthrift")
pipeline = RemediationPipeline(store)

# â”€â”€ Scanner registry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_SCANNER_MAP: dict[str, type] = {
    ResourceType.EC2_INSTANCE.value: EC2Scanner,
    ResourceType.EBS_VOLUME.value: EBSScanner,
    ResourceType.ELASTIC_IP.value: ElasticIPScanner,
    ResourceType.S3_BUCKET.value: S3Scanner,
    ResourceType.RDS_INSTANCE.value: RDSScanner,
    ResourceType.ELB.value: ELBScanner,
    ResourceType.LAMBDA_FUNCTION.value: LambdaScanner,
    ResourceType.EBS_SNAPSHOT.value: SnapshotScanner,
}

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _text(content: str) -> list[TextContent]:
    return [TextContent(type="text", text=content)]


def _json_text(obj: Any) -> list[TextContent]:
    return _text(json.dumps(obj, indent=2, default=str))


def _err(msg: str) -> list[TextContent]:
    return _text(f"ERROR: {msg}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TOOLS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="scan_resources",
            description=(
                "Scan AWS account(s) for orphaned, idle, or oversized resources that are "
                "wasting money. Returns a structured list of findings with severity, estimated "
                "monthly cost, and remediation recommendations. "
                "In DEMO_MODE, returns synthetic data without AWS credentials."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "resource_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Resource types to scan. Leave empty for all types. "
                            "Valid values: ec2_instance, ebs_volume, elastic_ip, s3_bucket, "
                            "rds_instance, elb, lambda_function, ebs_snapshot"
                        ),
                    },
                    "regions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "AWS regions to scan. Defaults to CLOUDTHRIFT_AWS_REGIONS.",
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Only return findings at or above this severity.",
                        "default": "LOW",
                    },
                },
            },
        ),
        Tool(
            name="get_findings",
            description=(
                "Query the current findings in memory. Filter by severity, resource type, "
                "region, or status. Returns a formatted table plus JSON data."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Filter by exact severity level.",
                    },
                    "resource_type": {
                        "type": "string",
                        "description": "Filter by resource type value (e.g. ebs_volume).",
                    },
                    "region": {"type": "string", "description": "Filter by AWS region."},
                    "status": {
                        "type": "string",
                        "enum": ["open", "planned", "remediated", "suppressed", "failed"],
                    },
                },
            },
        ),
        Tool(
            name="analyze_costs",
            description=(
                "Query AWS Cost Explorer for a spend breakdown by service, trend analysis, "
                "and projected monthly cost. Requires Cost Explorer enabled in the AWS account."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {
                        "type": "string",
                        "description": "ISO-8601 start date (YYYY-MM-DD). Default: 90 days ago.",
                    },
                    "end_date": {
                        "type": "string",
                        "description": "ISO-8601 end date (YYYY-MM-DD). Default: today.",
                    },
                    "granularity": {
                        "type": "string",
                        "enum": ["DAILY", "MONTHLY"],
                        "default": "MONTHLY",
                    },
                },
            },
        ),
        Tool(
            name="generate_waste_report",
            description=(
                "Generate a comprehensive waste report combining scan findings and cost data. "
                "Returns both a rich terminal view and a Markdown report suitable for "
                "sharing with stakeholders."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["terminal", "markdown", "both"],
                        "default": "both",
                        "description": "Output format.",
                    },
                    "include_cost_analysis": {
                        "type": "boolean",
                        "default": True,
                        "description": "Whether to include Cost Explorer data in the report.",
                    },
                },
            },
        ),
        Tool(
            name="create_remediation_plan",
            description=(
                "Build a remediation plan for a list of finding IDs. The plan is DRY-RUN by "
                "default â€” no AWS changes are made. Shows exactly what actions would be taken, "
                "estimated savings, and flags destructive operations for explicit approval."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of finding IDs to include in the plan.",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "default": True,
                        "description": "Set to false only after reviewing the plan and obtaining approval.",
                    },
                },
                "required": ["finding_ids"],
            },
        ),
        Tool(
            name="approve_remediation_plan",
            description=(
                "Approve a remediation plan so it can be executed. This is the human-in-the-loop "
                "gate that must be called before execute_remediation_plan for plans containing "
                "destructive actions. Requires explicit plan_id and approver name."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "plan_id": {"type": "string", "description": "Plan ID to approve (e.g. PLAN-AB1234)."},
                    "approved_by": {
                        "type": "string",
                        "description": "Name or identifier of the approver (recorded in audit log).",
                    },
                },
                "required": ["plan_id", "approved_by"],
            },
        ),
        Tool(
            name="execute_remediation_plan",
            description=(
                "Execute an approved remediation plan. Each step is executed sequentially with "
                "full audit logging. Destructive plans require prior approval via "
                "approve_remediation_plan. Returns a full execution report."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "plan_id": {"type": "string", "description": "Plan ID to execute."},
                },
                "required": ["plan_id"],
            },
        ),
        Tool(
            name="get_resource_details",
            description=(
                "Get the full details for a specific finding, including all metadata, "
                "cost breakdown, tags, and recommended remediation steps."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID (e.g. A1B2C3D4)."},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="suppress_finding",
            description=(
                "Mark a finding as suppressed (intentionally ignored). "
                "Suppressed findings are excluded from waste totals and future reports."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "reason": {"type": "string", "description": "Why this finding is being suppressed."},
                },
                "required": ["finding_id", "reason"],
            },
        ),
        Tool(
            name="get_audit_log",
            description="Retrieve the action audit trail showing all CloudThrift operations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "description": "Number of most-recent entries to return.",
                    },
                },
            },
        ),
    ]


# â”€â”€ Tool handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


@app.call_tool()
async def call_tool(
    name: str, arguments: dict[str, Any]
) -> list[TextContent | ImageContent | EmbeddedResource]:

    if name == "scan_resources":
        return await _tool_scan_resources(arguments)
    if name == "get_findings":
        return _tool_get_findings(arguments)
    if name == "analyze_costs":
        return await _tool_analyze_costs(arguments)
    if name == "generate_waste_report":
        return await _tool_waste_report(arguments)
    if name == "create_remediation_plan":
        return _tool_create_plan(arguments)
    if name == "approve_remediation_plan":
        return _tool_approve_plan(arguments)
    if name == "execute_remediation_plan":
        return _tool_execute_plan(arguments)
    if name == "get_resource_details":
        return _tool_get_resource(arguments)
    if name == "suppress_finding":
        return _tool_suppress(arguments)
    if name == "get_audit_log":
        return _tool_audit_log(arguments)

    return _err(f"Unknown tool: {name}")


# â”€â”€ Individual tool implementations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


async def _tool_scan_resources(args: dict[str, Any]) -> list[TextContent]:
    regions = args.get("regions") or _config.settings.aws_regions
    rt_filter = [ResourceType(v) for v in args.get("resource_types", [])]
    min_sev_str = args.get("min_severity", "LOW")
    sev_order = list(Severity)
    min_sev = Severity(min_sev_str)
    min_sev_index = sev_order.index(min_sev)

    # â”€â”€ Demo mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if _config.settings.demo_mode:
        demo_findings = generate_demo_findings()
        if rt_filter:
            demo_findings = [f for f in demo_findings if f.resource_type in rt_filter]
        demo_findings = [
            f for f in demo_findings if sev_order.index(f.severity) <= min_sev_index
        ]
        scan = ScanResult(
            regions=regions,
            resource_types=rt_filter or list(ResourceType),
            findings=demo_findings,
            scan_duration_seconds=1.23,
            completed_at=datetime.now(timezone.utc),
        )
        store.upsert_findings(demo_findings)
        store.set_latest_scan(scan)

        banner = render_demo_banner()
        summary = render_scan_summary(scan)
        table = render_findings_table(demo_findings)
        return _text(banner + "\n" + summary + "\n" + table)

    # â”€â”€ Real AWS scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    all_findings = []
    errors: list[str] = []
    start_time = time.time()

    scanner_classes = list(_SCANNER_MAP.items())
    if rt_filter:
        scanner_classes = [(k, v) for k, v in scanner_classes if ResourceType(k) in rt_filter]

    for region in regions:
        for rt_value, scanner_cls in scanner_classes:
            scanner = scanner_cls(region)
            findings, errs = scanner.safe_scan()
            all_findings.extend(findings)
            errors.extend(errs)

    # Filter by severity
    all_findings = [
        f for f in all_findings if sev_order.index(f.severity) <= min_sev_index
    ]

    # Respect per-scan limit
    all_findings = all_findings[: _config.settings.max_findings_per_scan]

    scan = ScanResult(
        regions=regions,
        resource_types=[ResourceType(k) for k, _ in scanner_classes],
        findings=all_findings,
        scan_duration_seconds=time.time() - start_time,
        completed_at=datetime.now(timezone.utc),
        errors=errors,
    )
    store.upsert_findings(all_findings)
    store.set_latest_scan(scan)

    summary = render_scan_summary(scan)
    table = render_findings_table(all_findings)
    return _text(summary + "\n" + table)


def _tool_get_findings(args: dict[str, Any]) -> list[TextContent]:
    findings = store.get_all_findings(
        status=FindingStatus(args["status"]) if args.get("status") else None,
        severity=args.get("severity"),
        resource_type=args.get("resource_type"),
        region=args.get("region"),
    )
    if not findings:
        return _text("No findings match the given filters. Run scan_resources first.")

    table = render_findings_table(findings)
    summary = (
        f"Found {len(findings)} findings  |  "
        f"Total monthly waste: ${sum(f.estimated_monthly_cost for f in findings):,.2f}"
    )
    return _text(table + "\n" + summary)


async def _tool_analyze_costs(args: dict[str, Any]) -> list[TextContent]:
    if _config.settings.demo_mode:
        return _text(
            render_demo_banner()
            + "\n[Demo mode] Cost Explorer data not available. "
            "Set CLOUDTHRIFT_DEMO_MODE=false to query real AWS Cost Explorer."
        )

    session = boto3.Session(region_name="us-east-1")
    analyzer = CostAnalyzer(session)
    analysis = analyzer.get_cost_analysis(
        start_date=args.get("start_date"),
        end_date=args.get("end_date"),
        granularity=args.get("granularity", "MONTHLY"),
    )
    return _text(render_cost_analysis(analysis))


async def _tool_waste_report(args: dict[str, Any]) -> list[TextContent]:
    fmt = args.get("format", "both")
    include_costs = args.get("include_cost_analysis", True)

    scan = store.get_latest_scan()
    if not scan:
        return _text(
            "No scan data available. Run scan_resources first to populate findings."
        )

    analysis = None
    if include_costs and not _config.settings.demo_mode:
        try:
            session = boto3.Session(region_name="us-east-1")
            analysis = CostAnalyzer(session).get_cost_analysis()
        except Exception:  # noqa: BLE001
            pass

    parts: list[str] = []

    if fmt in ("terminal", "both"):
        parts.append(render_scan_summary(scan))
        if analysis:
            parts.append(render_cost_analysis(analysis))

    if fmt in ("markdown", "both"):
        parts.append("\n---\n")
        parts.append(render_waste_report_markdown(scan, analysis))

    return _text("\n".join(parts))


def _tool_create_plan(args: dict[str, Any]) -> list[TextContent]:
    finding_ids: list[str] = args.get("finding_ids", [])
    dry_run: bool = args.get("dry_run", True)

    if not finding_ids:
        return _err("finding_ids must not be empty.")

    plan = pipeline.create_plan(finding_ids=finding_ids, dry_run=dry_run)
    findings = [store.get_finding(fid) for fid in finding_ids if store.get_finding(fid)]

    output = render_remediation_plan(plan, findings)  # type: ignore[arg-type]
    if plan.dry_run:
        output += (
            "\n[DRY-RUN] No AWS changes have been made.\n"
            "To execute for real:\n"
            "  1. Call approve_remediation_plan with the plan ID and your name.\n"
            "  2. Call execute_remediation_plan with the plan ID.\n"
        )
    else:
        output += (
            "\n[LIVE] Plan created with live execution mode.\n"
            "Call approve_remediation_plan then execute_remediation_plan to proceed.\n"
        )
    return _text(output)


def _tool_approve_plan(args: dict[str, Any]) -> list[TextContent]:
    plan_id: str = args.get("plan_id", "")
    approved_by: str = args.get("approved_by", "")

    if not plan_id or not approved_by:
        return _err("plan_id and approved_by are required.")

    try:
        plan = pipeline.approve_plan(plan_id=plan_id, approved_by=approved_by)
    except ValueError as exc:
        return _err(str(exc))

    destructive_count = sum(1 for s in plan.steps if s.is_destructive)
    return _text(
        f"Plan {plan_id} APPROVED by {approved_by}.\n"
        f"Steps: {len(plan.steps)}  |  Destructive: {destructive_count}  |  "
        f"Est. savings: ${plan.total_estimated_savings:,.2f}/mo\n\n"
        f"Call execute_remediation_plan(plan_id='{plan_id}') to proceed."
    )


def _tool_execute_plan(args: dict[str, Any]) -> list[TextContent]:
    plan_id: str = args.get("plan_id", "")
    if not plan_id:
        return _err("plan_id is required.")

    try:
        plan = pipeline.execute_plan(plan_id=plan_id)
    except (ValueError, PermissionError) as exc:
        return _err(str(exc))

    findings = [
        store.get_finding(step.finding_id)
        for step in plan.steps
        if store.get_finding(step.finding_id)
    ]

    output = render_remediation_plan(plan, findings)  # type: ignore[arg-type]
    completed = sum(1 for s in plan.steps if s.status == "completed")
    failed = sum(1 for s in plan.steps if s.status == "failed")
    dry = sum(1 for s in plan.steps if s.status == "dry_run")

    output += (
        f"\n\nExecution complete. "
        f"Completed: {completed}  Dry-run: {dry}  Failed: {failed}\n"
        f"Status: {plan.status.value.upper()}\n"
    )
    return _text(output)


def _tool_get_resource(args: dict[str, Any]) -> list[TextContent]:
    fid = args.get("finding_id", "")
    finding = store.get_finding(fid)
    if not finding:
        return _err(f"Finding {fid!r} not found. Run scan_resources first.")

    lines = [
        f"# Finding {finding.id}",
        f"",
        f"**Title:** {finding.title}",
        f"**Severity:** {finding.severity.value}",
        f"**Status:** {finding.status.value}",
        f"**Resource:** {finding.resource_type.label} â€” `{finding.resource_id}`",
        f"**Region:** {finding.region}",
        f"**Account:** {finding.account_id}",
        f"**Age:** {finding.age_days} days",
        f"",
        f"## Cost",
        f"- Monthly waste: **${finding.estimated_monthly_cost:,.2f}**",
        f"- Annual waste: **${finding.estimated_annual_cost:,.0f}**",
        f"",
        f"## Description",
        finding.description,
        f"",
        f"## Recommendation",
        finding.recommendation,
        f"",
        f"## Remediation Action",
        f"`{finding.remediation_action.value}` â€” {finding.remediation_action.verb}",
        f"Destructive: {'YES' if finding.remediation_action.is_destructive else 'No'}",
        f"",
    ]

    if finding.tags:
        lines.append("## Tags")
        for k, v in finding.tags.items():
            lines.append(f"- `{k}`: {v}")
        lines.append("")

    if finding.metadata:
        lines.append("## Metadata")
        for k, v in finding.metadata.items():
            lines.append(f"- **{k}:** {v}")

    return _text("\n".join(lines))


def _tool_suppress(args: dict[str, Any]) -> list[TextContent]:
    fid = args.get("finding_id", "")
    reason = args.get("reason", "")
    finding = store.get_finding(fid)
    if not finding:
        return _err(f"Finding {fid!r} not found.")

    store.update_finding_status(fid, FindingStatus.SUPPRESSED)
    from cloudthrift.models import AuditEntry
    store.append_audit(
        AuditEntry(
            action="suppress_finding",
            resource_id=finding.resource_id,
            resource_type=finding.resource_type.value,
            region=finding.region,
            details={"reason": reason, "finding_id": fid},
        )
    )
    return _text(
        f"Finding {fid} suppressed.\nReason: {reason}\n"
        f"Resource: {finding.resource_id} ({finding.resource_type.label})"
    )


def _tool_audit_log(args: dict[str, Any]) -> list[TextContent]:
    limit = args.get("limit", 50)
    entries = store.get_audit_log(limit=limit)
    if not entries:
        return _text("Audit log is empty.")

    lines = ["# CloudThrift Audit Log\n"]
    lines.append(f"Showing {len(entries)} most-recent entries.\n")
    lines.append("| Timestamp | Action | Resource | Region | Dry-run | Success |")
    lines.append("|-----------|--------|----------|--------|---------|---------|")
    for e in entries:
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(
            f"| {ts} | `{e.action}` | `{e.resource_id or 'â€”'}` "
            f"| {e.region or 'â€”'} | {'yes' if e.dry_run else 'NO'} "
            f"| {'âœ“' if e.success else 'âœ—'} |"
        )
    return _text("\n".join(lines))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# RESOURCES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


@app.list_resources()
async def list_resources() -> list[Resource]:
    return [
        Resource(
            uri=AnyUrl("cloudthrift://findings/all"),
            name="All Findings",
            description="JSON array of all current CloudThrift findings in memory.",
            mimeType="application/json",
        ),
        Resource(
            uri=AnyUrl("cloudthrift://report/latest"),
            name="Latest Scan Report",
            description="Markdown summary of the most-recent resource scan.",
            mimeType="text/markdown",
        ),
        Resource(
            uri=AnyUrl("cloudthrift://audit-log"),
            name="Audit Log",
            description="Full action audit trail as JSON.",
            mimeType="application/json",
        ),
        Resource(
            uri=AnyUrl("cloudthrift://config"),
            name="Configuration",
            description="Current CloudThrift configuration (redacted).",
            mimeType="application/json",
        ),
    ]


@app.read_resource()
async def read_resource(uri: AnyUrl) -> str:
    uri_str = str(uri)

    if uri_str == "cloudthrift://findings/all":
        findings = store.get_all_findings()
        return json.dumps([f.to_summary_dict() for f in findings], indent=2)

    if uri_str == "cloudthrift://report/latest":
        scan = store.get_latest_scan()
        if not scan:
            return "# No scan data\n\nRun the `scan_resources` tool first."
        return render_waste_report_markdown(scan)

    if uri_str == "cloudthrift://audit-log":
        entries = store.get_audit_log(limit=200)
        return json.dumps([e.model_dump(mode="json") for e in entries], indent=2, default=str)

    if uri_str == "cloudthrift://config":
        cfg = {
            "aws_regions": _config.settings.aws_regions,
            "demo_mode": _config.settings.demo_mode,
            "stopped_instance_age_days": _config.settings.stopped_instance_age_days,
            "unattached_volume_age_days": _config.settings.unattached_volume_age_days,
            "old_snapshot_days": _config.settings.old_snapshot_days,
            "s3_inactive_days": _config.settings.s3_inactive_days,
            "unused_lambda_days": _config.settings.unused_lambda_days,
            "max_findings_per_scan": _config.settings.max_findings_per_scan,
            "require_approval_for_destructive": _config.settings.require_approval_for_destructive,
        }
        return json.dumps(cfg, indent=2)

    raise ValueError(f"Unknown resource URI: {uri_str}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PROMPTS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


@app.list_prompts()
async def list_prompts() -> list[Prompt]:
    return [
        Prompt(
            name="finops_advisor",
            description=(
                "Start a FinOps advisory session. CloudThrift will scan the account, "
                "analyse costs, and provide prioritised savings recommendations."
            ),
            arguments=[
                PromptArgument(
                    name="focus",
                    description="Optional focus area: compute | storage | database | network | all",
                    required=False,
                ),
                PromptArgument(
                    name="budget_threshold",
                    description="Monthly waste threshold in USD to report on (default: 20)",
                    required=False,
                ),
            ],
        ),
        Prompt(
            name="remediation_guide",
            description=(
                "Interactive remediation guide. CloudThrift walks you through each finding "
                "step-by-step, explaining risks, seeking your approval, and executing safely."
            ),
            arguments=[
                PromptArgument(
                    name="plan_id",
                    description="Existing remediation plan ID to continue, or leave empty to create a new one.",
                    required=False,
                ),
                PromptArgument(
                    name="dry_run",
                    description="Run in dry-run mode (default: true). Set to false for live execution.",
                    required=False,
                ),
            ],
        ),
        Prompt(
            name="weekly_finops_report",
            description=(
                "Generate an executive-ready weekly FinOps summary with trend analysis, "
                "top waste contributors, and recommended actions."
            ),
            arguments=[],
        ),
    ]


@app.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
    args = arguments or {}

    if name == "finops_advisor":
        focus = args.get("focus", "all")
        threshold = args.get("budget_threshold", "20")
        return GetPromptResult(
            description="CloudThrift FinOps Advisory Session",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=(
                            f"You are CloudThrift, an expert FinOps engineer and AWS SRE. "
                            f"Your mission is to identify cloud waste and help the team "
                            f"reduce AWS spend without compromising reliability.\n\n"
                            f"Focus area: {focus}\n"
                            f"Report findings costing more than ${threshold}/mo.\n\n"
                            f"Please:\n"
                            f"1. Run scan_resources to identify orphaned resources\n"
                            f"2. Run analyze_costs to understand current spend patterns\n"
                            f"3. Generate a waste report with generate_waste_report\n"
                            f"4. Prioritise findings by financial impact\n"
                            f"5. For the top findings, ask the user whether to create a "
                            f"remediation plan\n\n"
                            f"Always explain WHY a resource is wasteful and WHAT the safe "
                            f"remediation approach is before taking any action."
                        ),
                    ),
                )
            ],
        )

    if name == "remediation_guide":
        plan_id = args.get("plan_id", "")
        dry_run = args.get("dry_run", "true").lower() != "false"
        mode = "DRY-RUN (safe preview)" if dry_run else "LIVE EXECUTION"
        return GetPromptResult(
            description="CloudThrift Safe Remediation Guide",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=(
                            f"You are CloudThrift, executing a careful remediation session "
                            f"in {mode} mode.\n\n"
                            f"{'Continuing plan: ' + plan_id if plan_id else 'Starting a fresh remediation session.'}\n\n"
                            f"For each finding:\n"
                            f"1. Present the resource details with get_resource_details\n"
                            f"2. Explain the risk of the resource and the risk of removing it\n"
                            f"3. Ask the user to confirm before adding to the plan\n"
                            f"4. Create the remediation plan with create_remediation_plan\n"
                            f"5. Show the full plan and ask for final approval\n"
                            f"6. {'Call approve_remediation_plan then execute.' if not dry_run else 'Execute in dry-run mode to preview actions.'}\n\n"
                            f"NEVER execute destructive actions without explicit user confirmation. "
                            f"Always prefer reversible actions (stop, tag) over irreversible ones (delete, terminate)."
                        ),
                    ),
                )
            ],
        )

    if name == "weekly_finops_report":
        return GetPromptResult(
            description="Weekly FinOps Executive Report",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=(
                            "Generate an executive-ready weekly FinOps report.\n\n"
                            "Steps:\n"
                            "1. Run scan_resources across all regions\n"
                            "2. Run analyze_costs for the last 30 days\n"
                            "3. Run generate_waste_report(format='markdown')\n"
                            "4. Summarise in this structure:\n\n"
                            "   ## This Week's Cloud Spend Summary\n"
                            "   - Total spend vs last week\n"
                            "   - Top 3 cost drivers\n"
                            "   - New waste detected this week\n"
                            "   - Cumulative savings from remediations\n"
                            "   - Recommended actions for next week (with effort estimates)\n\n"
                            "Use numbers, percentages, and dollar amounts throughout. "
                            "The report should be understandable by non-technical stakeholders."
                        ),
                    ),
                )
            ],
        )

    raise ValueError(f"Unknown prompt: {name}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ENTRY POINT
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


async def _serve() -> None:
    logger.info("CloudThrift MCP Server starting (demo_mode=%s)", _config.settings.demo_mode)
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


@click.command()
@click.option("--demo", is_flag=True, default=False, help="Enable demo mode (no AWS credentials needed)")
@click.option("--region", multiple=True, help="AWS region(s) to scan (repeatable)")
def main(demo: bool, region: tuple[str, ...]) -> None:
    """CloudThrift â€” Enterprise FinOps MCP Server."""
    if demo:
        import os
        os.environ["CLOUDTHRIFT_DEMO_MODE"] = "true"

    if region:
        import os
        os.environ["CLOUDTHRIFT_AWS_REGIONS"] = json.dumps(list(region))

    # Reload settings after env var injection
    from cloudthrift import config as cfg_module
    cfg_module.settings = cfg_module.CloudThriftConfig()

    asyncio.run(_serve())


if __name__ == "__main__":
    main()

