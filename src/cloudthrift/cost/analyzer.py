"""AWS Cost Explorer integration for spend analysis and waste attribution."""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError, NoCredentialsError
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ServiceCost(BaseModel):
    service: str
    period: str
    amount: float
    currency: str = "USD"
    unit: str = "USD"


class CostTrend(BaseModel):
    """Month-over-month cost trend for a service or total."""
    service: str
    months: list[str]
    amounts: list[float]
    currency: str = "USD"
    change_pct: float = 0.0
    trend: str = "stable"  # "rising", "falling", "stable"

    def model_post_init(self, __context: Any) -> None:
        if len(self.amounts) >= 2 and self.amounts[-2] > 0:
            self.change_pct = ((self.amounts[-1] - self.amounts[-2]) / self.amounts[-2]) * 100
            if self.change_pct > 5:
                self.trend = "rising"
            elif self.change_pct < -5:
                self.trend = "falling"
            else:
                self.trend = "stable"


class CostAnalysis(BaseModel):
    start_date: str
    end_date: str
    total_cost: float
    currency: str = "USD"
    by_service: list[ServiceCost]
    trends: list[CostTrend]
    top_services: list[ServiceCost]
    daily_average: float = 0.0
    projected_monthly: float = 0.0
    generated_at: datetime

    def model_post_init(self, __context: Any) -> None:
        days = max(
            1,
            (
                date.fromisoformat(self.end_date) - date.fromisoformat(self.start_date)
            ).days,
        )
        self.daily_average = self.total_cost / days
        self.projected_monthly = self.daily_average * 30


class CostAnalyzer:
    """Wraps AWS Cost Explorer for FinOps-grade cost intelligence."""

    def __init__(self, session: Any) -> None:
        self._ce = session.client("ce", region_name="us-east-1")

    def get_cost_analysis(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
        granularity: str = "MONTHLY",
    ) -> CostAnalysis:
        today = date.today()
        if not end_date:
            end_date = today.isoformat()
        if not start_date:
            # Default: last 3 months
            start_date = (today - timedelta(days=90)).isoformat()

        try:
            by_service = self._get_cost_by_service(start_date, end_date, granularity)
            trends = self._get_trends(today)
            total = sum(s.amount for s in by_service)
            top_services = sorted(by_service, key=lambda x: x.amount, reverse=True)[:10]

            return CostAnalysis(
                start_date=start_date,
                end_date=end_date,
                total_cost=total,
                by_service=by_service,
                trends=trends,
                top_services=top_services,
                generated_at=datetime.now(timezone.utc),
            )
        except (ClientError, NoCredentialsError) as exc:
            logger.warning("Cost Explorer unavailable: %s", exc)
            return self._stub_analysis(start_date, end_date)

    def _get_cost_by_service(
        self, start: str, end: str, granularity: str
    ) -> list[ServiceCost]:
        results: list[ServiceCost] = []
        try:
            resp = self._ce.get_cost_and_usage(
                TimePeriod={"Start": start, "End": end},
                Granularity=granularity,
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDeniedException", "OptInRequired"):
                logger.warning("Cost Explorer not enabled or no permission: %s", exc)
                return []
            raise

        # Aggregate across all time periods
        service_totals: dict[str, float] = {}
        period_label = f"{start} to {end}"
        for time_result in resp.get("ResultsByTime", []):
            for group in time_result.get("Groups", []):
                svc = group["Keys"][0]
                amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                service_totals[svc] = service_totals.get(svc, 0.0) + amount

        for svc, amount in service_totals.items():
            if amount > 0.01:
                results.append(ServiceCost(service=svc, period=period_label, amount=round(amount, 4)))

        return sorted(results, key=lambda x: x.amount, reverse=True)

    def _get_trends(self, today: date) -> list[CostTrend]:
        """Build 6-month monthly cost trend per service."""
        trends: list[CostTrend] = []
        start = (today.replace(day=1) - timedelta(days=150)).replace(day=1)
        end = today

        try:
            resp = self._ce.get_cost_and_usage(
                TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
        except ClientError:
            return []

        # Build month → service → cost
        monthly: dict[str, dict[str, float]] = {}
        for time_result in resp.get("ResultsByTime", []):
            month = time_result["TimePeriod"]["Start"][:7]
            monthly[month] = {}
            for group in time_result.get("Groups", []):
                svc = group["Keys"][0]
                amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                monthly[month][svc] = amount

        if not monthly:
            return []

        months = sorted(monthly.keys())
        all_services = {svc for mo in monthly.values() for svc in mo}

        total_by_month = [sum(monthly[m].values()) for m in months]
        trends.append(CostTrend(service="Total", months=months, amounts=total_by_month))

        # Top services by last month spend
        last_month = monthly[months[-1]] if months else {}
        for svc in sorted(last_month, key=lambda s: last_month[s], reverse=True)[:5]:
            amounts = [monthly[m].get(svc, 0.0) for m in months]
            trends.append(CostTrend(service=svc, months=months, amounts=amounts))

        return trends

    def get_resource_level_costs(self, tag_key: str = "Name") -> dict[str, float]:
        """Use Cost Explorer tags dimension to get per-resource costs."""
        today = date.today()
        start = (today - timedelta(days=30)).isoformat()
        try:
            resp = self._ce.get_cost_and_usage(
                TimePeriod={"Start": start, "End": today.isoformat()},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "TAG", "Key": tag_key}],
            )
            costs: dict[str, float] = {}
            for tr in resp.get("ResultsByTime", []):
                for group in tr.get("Groups", []):
                    tag_value = group["Keys"][0].replace(f"{tag_key}$", "")
                    costs[tag_value] = costs.get(tag_value, 0.0) + float(
                        group["Metrics"]["UnblendedCost"]["Amount"]
                    )
            return costs
        except ClientError:
            return {}

    @staticmethod
    def _stub_analysis(start: str, end: str) -> CostAnalysis:
        """Return a minimal stub when Cost Explorer is unavailable."""
        return CostAnalysis(
            start_date=start,
            end_date=end,
            total_cost=0.0,
            by_service=[],
            trends=[],
            top_services=[],
            generated_at=datetime.now(timezone.utc),
        )
