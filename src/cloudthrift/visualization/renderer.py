"""Rich terminal renderer for CloudThrift reports.

All public methods return a plain string (captured from Rich console) so they
can be embedded directly in MCP TextContent responses.
"""

from __future__ import annotations

import io
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from cloudthrift.cost.analyzer import CostAnalysis
from cloudthrift.models import (
    Finding,
    FindingStatus,
    RemediationPlan,
    ScanResult,
    Severity,
)


def _console(width: int = 120) -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    con = Console(file=buf, width=width, highlight=False, markup=True)
    return con, buf


# ── Severity badge ────────────────────────────────────────────────────────────

def _sev_badge(sev: Severity) -> str:
    icons = {
        Severity.CRITICAL: "[bold red]◉ CRITICAL[/]",
        Severity.HIGH:     "[red]● HIGH    [/]",
        Severity.MEDIUM:   "[yellow]● MEDIUM  [/]",
        Severity.LOW:      "[cyan]● LOW     [/]",
        Severity.INFO:     "[dim]○ INFO    [/]",
    }
    return icons.get(sev, sev.value)


# ── ASCII bar chart ───────────────────────────────────────────────────────────

def _bar(value: float, max_value: float, width: int = 30, color: str = "green") -> str:
    if max_value == 0:
        return " " * width
    filled = int((value / max_value) * width)
    return f"[{color}]{'█' * filled}[/][dim]{'░' * (width - filled)}[/]"


# ── Findings table ────────────────────────────────────────────────────────────

def render_findings_table(findings: list[Finding], title: str = "CloudThrift Findings") -> str:
    con, buf = _console()

    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        row_styles=["", "dim"],
        show_lines=False,
        expand=True,
    )
    table.add_column("ID", style="bold", width=8)
    table.add_column("Sev", width=12)
    table.add_column("Type", width=18)
    table.add_column("Resource", overflow="fold", width=28)
    table.add_column("Region", width=14)
    table.add_column("Monthly Waste", justify="right", width=14)
    table.add_column("Age (days)", justify="right", width=10)
    table.add_column("Status", width=12)

    for f in findings:
        age_str = str(f.age_days) if f.age_days > 0 else "—"
        status_color = {
            FindingStatus.OPEN: "green",
            FindingStatus.PLANNED: "yellow",
            FindingStatus.REMEDIATED: "dim",
            FindingStatus.SUPPRESSED: "dim",
            FindingStatus.FAILED: "red",
        }.get(f.status, "white")

        table.add_row(
            f.id,
            _sev_badge(f.severity),
            f.resource_type.label,
            f.resource_name or f.resource_id,
            f.region,
            f"[bold]${f.estimated_monthly_cost:,.2f}[/]" if f.estimated_monthly_cost > 0 else "—",
            age_str,
            f"[{status_color}]{f.status.value}[/]",
        )

    con.print(table)
    return buf.getvalue()


# ── Scan summary panel ────────────────────────────────────────────────────────

def render_scan_summary(result: ScanResult) -> str:
    con, buf = _console()

    # Header
    con.print(Panel(
        f"[bold cyan]CloudThrift Scan Report[/]  ·  Scan ID: [bold]{result.scan_id}[/]\n"
        f"Regions: {', '.join(result.regions)}  ·  "
        f"Duration: {result.scan_duration_seconds:.1f}s",
        border_style="cyan",
        expand=False,
    ))

    # Severity breakdown
    sev_counts = {s: 0 for s in Severity}
    for f in result.findings:
        sev_counts[f.severity] += 1

    waste_table = Table(box=None, show_header=False, pad_edge=False)
    waste_table.add_column(width=14)
    waste_table.add_column(width=6, justify="right")
    waste_table.add_column(width=32)

    max_count = max(sev_counts.values(), default=1)
    for sev in Severity:
        count = sev_counts[sev]
        waste_table.add_row(
            _sev_badge(sev),
            f"[bold]{count}[/]",
            _bar(count, max_count, width=28, color=sev.color.split()[0]),
        )

    con.print(waste_table)

    # Financial summary
    monthly = result.total_monthly_waste
    annual = result.total_annual_waste
    con.print(
        f"\n[bold]Total findings:[/] {result.total_findings}   "
        f"[bold red]Monthly waste:[/] [bold]${monthly:,.2f}[/]   "
        f"[bold red]Annual waste:[/] [bold]${annual:,.0f}[/]\n"
    )

    # Top 5 most expensive findings
    if result.findings:
        top5 = sorted(result.findings, key=lambda f: f.estimated_monthly_cost, reverse=True)[:5]
        con.print("[bold cyan]Top 5 Cost Contributors[/]")
        top_table = Table(box=None, show_header=False, pad_edge=False)
        top_table.add_column(width=30, overflow="fold")
        top_table.add_column(width=14, justify="right")
        top_table.add_column(width=40)

        max_cost = top5[0].estimated_monthly_cost if top5 else 1
        for f in top5:
            top_table.add_row(
                f.resource_name or f.resource_id,
                f"[bold]${f.estimated_monthly_cost:,.2f}/mo[/]",
                _bar(f.estimated_monthly_cost, max_cost, width=36, color="red"),
            )
        con.print(top_table)

    # Errors
    if result.errors:
        con.print("\n[yellow]⚠  Scan errors (non-fatal):[/]")
        for err in result.errors:
            con.print(f"  [dim]{err}[/]")

    return buf.getvalue()


# ── Cost analysis report ───────────────────────────────────────────────────────

def render_cost_analysis(analysis: CostAnalysis) -> str:
    con, buf = _console()

    con.print(Panel(
        f"[bold cyan]AWS Cost Analysis[/]  ·  "
        f"{analysis.start_date} → {analysis.end_date}\n"
        f"Total: [bold]${analysis.total_cost:,.2f}[/]   "
        f"Daily avg: [bold]${analysis.daily_average:,.2f}[/]   "
        f"Projected monthly: [bold]${analysis.projected_monthly:,.2f}[/]",
        border_style="cyan",
        expand=False,
    ))

    if analysis.top_services:
        con.print("\n[bold]Top Services by Spend[/]")
        tbl = Table(box=None, show_header=False, pad_edge=False)
        tbl.add_column(width=34, overflow="fold")
        tbl.add_column(width=12, justify="right")
        tbl.add_column(width=38)
        tbl.add_column(width=8, justify="right")

        max_amt = analysis.top_services[0].amount if analysis.top_services else 1
        total = analysis.total_cost or 1
        for svc in analysis.top_services:
            pct = (svc.amount / total) * 100
            tbl.add_row(
                svc.service,
                f"[bold]${svc.amount:,.2f}[/]",
                _bar(svc.amount, max_amt, width=34, color="blue"),
                f"[dim]{pct:.1f}%[/]",
            )
        con.print(tbl)

    # Trend indicators
    if analysis.trends:
        total_trend = next((t for t in analysis.trends if t.service == "Total"), None)
        if total_trend:
            arrow = {"rising": "↑", "falling": "↓", "stable": "→"}[total_trend.trend]
            trend_color = {"rising": "red", "falling": "green", "stable": "yellow"}[total_trend.trend]
            con.print(
                f"\nMoM trend: [{trend_color}][bold]{arrow} {abs(total_trend.change_pct):.1f}%[/][/]  "
                f"({total_trend.trend})"
            )

    return buf.getvalue()


# ── Remediation plan report ───────────────────────────────────────────────────

def render_remediation_plan(plan: RemediationPlan, findings: list[Finding]) -> str:
    con, buf = _console()

    dry_label = "[yellow]DRY-RUN[/]" if plan.dry_run else "[bold red]LIVE EXECUTION[/]"

    con.print(Panel(
        f"[bold cyan]Remediation Plan[/]  {dry_label}  ·  {plan.id}\n"
        f"Status: [bold]{plan.status.value.upper()}[/]   "
        f"Steps: {len(plan.steps)}   "
        f"Est. monthly savings: [bold green]${plan.total_estimated_savings:,.2f}[/]   "
        f"(${plan.annual_estimated_savings:,.0f}/yr)",
        border_style="cyan",
        expand=False,
    ))

    # Steps table
    tbl = Table(
        show_header=True,
        header_style="bold",
        border_style="cyan",
        show_lines=False,
        expand=True,
    )
    tbl.add_column("#", width=4, justify="right")
    tbl.add_column("Action", width=30)
    tbl.add_column("Resource", overflow="fold", width=28)
    tbl.add_column("Region", width=14)
    tbl.add_column("Savings/mo", justify="right", width=12)
    tbl.add_column("Destructive", width=11, justify="center")
    tbl.add_column("Status", width=12)

    for i, step in enumerate(plan.steps, 1):
        dest_badge = "[bold red]YES[/]" if step.is_destructive else "[green]no[/]"
        status_color = {
            "pending": "dim",
            "completed": "green",
            "failed": "red",
            "dry_run": "yellow",
        }.get(step.status, "white")

        tbl.add_row(
            str(i),
            step.action.verb,
            step.resource_id,
            step.region,
            f"${step.estimated_savings:,.2f}" if step.estimated_savings > 0 else "—",
            dest_badge,
            f"[{status_color}]{step.status}[/]",
        )

    con.print(tbl)

    if plan.execution_log:
        con.print("\n[bold]Execution Log[/]")
        for line in plan.execution_log[-20:]:
            con.print(f"  [dim]{line}[/]")

    return buf.getvalue()


# ── Waste report (markdown-friendly) ─────────────────────────────────────────

def render_waste_report_markdown(
    result: ScanResult,
    analysis: CostAnalysis | None = None,
) -> str:
    """Generate a Markdown waste report suitable for GitHub, Confluence, etc."""
    lines: list[str] = []
    lines.append("# CloudThrift — Waste Report")
    lines.append(f"\n**Scan ID:** `{result.scan_id}`  |  "
                 f"**Regions:** {', '.join(result.regions)}  |  "
                 f"**Generated:** {result.started_at.strftime('%Y-%m-%d %H:%M UTC')}\n")

    monthly = result.total_monthly_waste
    annual = result.total_annual_waste
    lines.append("## Executive Summary\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total findings | **{result.total_findings}** |")
    lines.append(f"| Monthly waste | **${monthly:,.2f}** |")
    lines.append(f"| Annual waste | **${annual:,.0f}** |")
    lines.append(f"| Scan duration | {result.scan_duration_seconds:.1f}s |")
    lines.append("")

    # Severity breakdown
    sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in result.findings:
        sev_counts[f.severity.value] += 1

    lines.append("## Severity Breakdown\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in Severity:
        lines.append(f"| {sev.value} | {sev_counts[sev.value]} |")
    lines.append("")

    # Findings by type
    lines.append("## Findings by Resource Type\n")
    by_type = result.findings_by_type
    lines.append("| Resource Type | Count | Monthly Waste |")
    lines.append("|---------------|-------|---------------|")
    for rtype, flist in sorted(by_type.items(), key=lambda x: sum(f.estimated_monthly_cost for f in x[1]), reverse=True):
        total = sum(f.estimated_monthly_cost for f in flist)
        lines.append(f"| {rtype} | {len(flist)} | ${total:,.2f} |")
    lines.append("")

    # Top 10 findings
    lines.append("## Top Findings\n")
    lines.append("| ID | Severity | Type | Resource | Region | Monthly Waste | Recommendation |")
    lines.append("|----|----------|------|----------|--------|---------------|----------------|")
    top = sorted(result.findings, key=lambda f: f.estimated_monthly_cost, reverse=True)[:10]
    for f in top:
        rec_short = f.recommendation[:60] + "…" if len(f.recommendation) > 60 else f.recommendation
        lines.append(
            f"| `{f.id}` | {f.severity.value} | {f.resource_type.label} "
            f"| `{f.resource_id}` | {f.region} | ${f.estimated_monthly_cost:,.2f} | {rec_short} |"
        )
    lines.append("")

    if analysis and analysis.top_services:
        lines.append("## Current AWS Spend\n")
        lines.append(f"Period: {analysis.start_date} → {analysis.end_date}  "
                     f"| Total: **${analysis.total_cost:,.2f}**\n")
        lines.append("| Service | Cost |")
        lines.append("|---------|------|")
        for svc in analysis.top_services[:8]:
            lines.append(f"| {svc.service} | ${svc.amount:,.2f} |")
        lines.append("")

    return "\n".join(lines)


# ── Demo / synthetic data rendering ──────────────────────────────────────────

def render_demo_banner() -> str:
    con, buf = _console()
    con.print(Panel(
        "[bold yellow]⚡ DEMO MODE[/]  —  CloudThrift is running with synthetic data.\n"
        "Set [bold]CLOUDTHRIFT_DEMO_MODE=false[/] and configure AWS credentials "
        "to scan a real account.",
        border_style="yellow",
        expand=False,
    ))
    return buf.getvalue()
