from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .models import AdmissionDecision, SourceRecord


WEEKLY_POLICY_VERSION = "r3-weekly-intake-v1"
_DATE_FIELDS = {
    "openalex": ("publication_date",),
    "arxiv": ("updated", "published"),
    "github": ("pushed_at", "updated_at", "created_at"),
}


class WeeklyIntakePolicyError(ValueError):
    pass


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WeeklyIntakePolicyError(f"{field} must be a positive integer")
    return value


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(normalized[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def record_activity_time(record: SourceRecord) -> tuple[datetime | None, str | None]:
    for field in _DATE_FIELDS.get(record.source, ()):
        parsed = _parse_datetime(record.metadata.get(field))
        if parsed is not None:
            return parsed, field
    return None, None


@dataclass(frozen=True, slots=True)
class WeeklyIntakePolicy:
    window_days: int
    overlap_days: int
    maximum_admitted_candidates: int
    source_query_caps: dict[str, int]
    query_caps: dict[str, int]
    lane_caps: dict[str, int]
    capacity_basis: dict[str, Any]

    @classmethod
    def from_config(cls, raw: dict[str, Any]) -> "WeeklyIntakePolicy":
        profile_version = raw.get("profile_version")
        intake = raw.get("intake")
        weekly = intake.get("weekly") if isinstance(intake, dict) else None
        if not isinstance(weekly, dict):
            raise WeeklyIntakePolicyError(
                "weekly mode requires an explicitly activated profile-v2 intake policy"
            )
        if profile_version is None or int(profile_version) < 2:
            raise WeeklyIntakePolicyError(
                "weekly intake activation requires profile_version >= 2"
            )
        if weekly.get("state") != "active":
            raise WeeklyIntakePolicyError(
                "weekly intake policy state must be active after explicit user confirmation"
            )
        if weekly.get("policy_version") != WEEKLY_POLICY_VERSION:
            raise WeeklyIntakePolicyError("unsupported weekly intake policy_version")

        window_days = _positive_integer(weekly.get("window_days"), "window_days")
        overlap_days = _positive_integer(weekly.get("overlap_days"), "overlap_days")
        maximum = _positive_integer(
            weekly.get("maximum_admitted_candidates"),
            "maximum_admitted_candidates",
        )
        source_caps = weekly.get("source_query_caps")
        query_caps = weekly.get("query_caps")
        lane_caps = weekly.get("lane_caps")
        if not isinstance(source_caps, dict) or not source_caps:
            raise WeeklyIntakePolicyError("source_query_caps must be a non-empty object")
        if not isinstance(query_caps, dict) or not query_caps:
            raise WeeklyIntakePolicyError("query_caps must be a non-empty object")
        if not isinstance(lane_caps, dict) or not lane_caps:
            raise WeeklyIntakePolicyError("lane_caps must be a non-empty object")
        normalized_sources = {
            str(key): _positive_integer(value, f"source_query_caps.{key}")
            for key, value in source_caps.items()
        }
        normalized_queries = {
            str(key): _positive_integer(value, f"query_caps.{key}")
            for key, value in query_caps.items()
        }
        normalized_lanes = {
            str(key): _positive_integer(value, f"lane_caps.{key}")
            for key, value in lane_caps.items()
        }
        configured_sources = {
            str(source)
            for query in raw.get("queries") or []
            for source in query.get("sources") or []
        }
        if (raw.get("hosted_search") or {}).get("enabled"):
            configured_sources.add("codex_web")
        configured_queries = {
            str(query.get("id")) for query in raw.get("queries") or []
        }
        configured_lanes = {
            str(query.get("lane")) for query in raw.get("queries") or []
        }
        missing_sources = configured_sources - normalized_sources.keys()
        missing_queries = configured_queries - normalized_queries.keys()
        missing_lanes = configured_lanes - normalized_lanes.keys()
        if missing_sources:
            raise WeeklyIntakePolicyError(
                "source_query_caps missing configured sources: "
                + ", ".join(sorted(missing_sources))
            )
        if missing_queries:
            raise WeeklyIntakePolicyError(
                "query_caps missing configured queries: "
                + ", ".join(sorted(missing_queries))
            )
        if missing_lanes:
            raise WeeklyIntakePolicyError(
                "lane_caps missing configured lanes: "
                + ", ".join(sorted(missing_lanes))
            )
        if sum(normalized_lanes.values()) < maximum:
            raise WeeklyIntakePolicyError(
                "lane_caps cannot accommodate maximum_admitted_candidates"
            )
        capacity_basis = weekly.get("capacity_basis")
        if not isinstance(capacity_basis, dict):
            raise WeeklyIntakePolicyError("capacity_basis must be an object")
        derived = capacity_basis.get("derived_maximum_admitted_candidates")
        if derived != maximum:
            raise WeeklyIntakePolicyError(
                "maximum_admitted_candidates must equal the measured capacity basis"
            )
        return cls(
            window_days=window_days,
            overlap_days=overlap_days,
            maximum_admitted_candidates=maximum,
            source_query_caps=normalized_sources,
            query_caps=normalized_queries,
            lane_caps=normalized_lanes,
            capacity_basis=dict(capacity_basis),
        )

    def retrieval_limit(
        self,
        *,
        source: str,
        query_id: str,
        requested_limit: int | None,
    ) -> int:
        configured = min(
            self.source_query_caps[source],
            self.query_caps[query_id.removeprefix("web-")],
        )
        if requested_limit is None:
            return configured
        return min(configured, max(1, int(requested_limit)))


class WeeklyIntakeGate:
    def __init__(
        self,
        policy: WeeklyIntakePolicy,
        *,
        now: datetime | None = None,
        admitted: Iterable[tuple[str, str]] = (),
    ):
        self.policy = policy
        reference = now or datetime.now(timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        self.reference_time = reference.astimezone(timezone.utc)
        self.window_start = self.reference_time - timedelta(
            days=policy.window_days + policy.overlap_days
        )
        self._admitted_keys: set[str] = set()
        self._lane_counts = {lane: 0 for lane in policy.lane_caps}
        self._reason_counts: dict[str, int] = {}
        for canonical_key, lane in admitted:
            if canonical_key in self._admitted_keys:
                continue
            self._admitted_keys.add(canonical_key)
            if lane in self._lane_counts:
                self._lane_counts[lane] += 1

    def source_job(self, job: dict[str, Any]) -> dict[str, Any]:
        return {
            **job,
            "weekly_since": self.window_start.date().isoformat(),
        }

    def retrieval_limit(
        self,
        job: dict[str, Any],
        requested_limit: int | None,
    ) -> int:
        return self.policy.retrieval_limit(
            source=str(job["source"]),
            query_id=str(job["query_id"]),
            requested_limit=requested_limit,
        )

    def _defer(self, code: str, reason: str) -> AdmissionDecision:
        self._reason_counts[code] = self._reason_counts.get(code, 0) + 1
        return AdmissionDecision(
            admitted=False,
            code=code,
            lane="intake_deferred",
            reason=reason,
        )

    def reserve(
        self,
        record: SourceRecord,
        base_decision: AdmissionDecision,
        *,
        query_lane: str,
        identity_key: str | None = None,
    ) -> tuple[AdmissionDecision, tuple[str, str] | None]:
        if not base_decision.admitted:
            return base_decision, None
        activity_time, date_field = record_activity_time(record)
        if activity_time is None:
            return (
                self._defer(
                    "weekly_date_unknown",
                    "Weekly admission requires a source-provided activity date; "
                    "the record remains visible for review.",
                ),
                None,
            )
        if activity_time < self.window_start:
            return (
                self._defer(
                    "weekly_outside_window",
                    f"Source field {date_field} precedes the weekly window start "
                    f"{self.window_start.date().isoformat()}.",
                ),
                None,
            )
        canonical_key = identity_key or record.canonical_key()
        if canonical_key in self._admitted_keys:
            return base_decision, None
        if query_lane not in self.policy.lane_caps:
            return (
                self._defer(
                    "weekly_lane_unconfigured",
                    f"Query lane {query_lane!r} has no activated weekly capacity.",
                ),
                None,
            )
        if len(self._admitted_keys) >= self.policy.maximum_admitted_candidates:
            return (
                self._defer(
                    "weekly_capacity_deferred",
                    "Measured six-hour full-read capacity is already allocated.",
                ),
                None,
            )
        if self._lane_counts[query_lane] >= self.policy.lane_caps[query_lane]:
            return (
                self._defer(
                    "weekly_lane_capacity_deferred",
                    f"Measured weekly capacity for lane {query_lane!r} is already allocated.",
                ),
                None,
            )
        self._admitted_keys.add(canonical_key)
        self._lane_counts[query_lane] += 1
        return base_decision, (canonical_key, query_lane)

    def commit(
        self,
        reservation: tuple[str, str] | None,
        *,
        stable_identity_key: str,
    ) -> None:
        if reservation is None:
            return
        provisional_key, query_lane = reservation
        if provisional_key == stable_identity_key:
            return
        if provisional_key not in self._admitted_keys:
            raise RuntimeError("weekly intake reservation was lost before commit")
        if stable_identity_key in self._admitted_keys:
            self._admitted_keys.remove(provisional_key)
            self._lane_counts[query_lane] = max(
                0,
                self._lane_counts.get(query_lane, 0) - 1,
            )
            return
        self._admitted_keys.remove(provisional_key)
        self._admitted_keys.add(stable_identity_key)

    def rollback(self, reservation: tuple[str, str] | None) -> None:
        if reservation is None:
            return
        canonical_key, query_lane = reservation
        if canonical_key not in self._admitted_keys:
            return
        self._admitted_keys.remove(canonical_key)
        self._lane_counts[query_lane] = max(
            0,
            self._lane_counts.get(query_lane, 0) - 1,
        )

    def decide(
        self,
        record: SourceRecord,
        base_decision: AdmissionDecision,
        *,
        query_lane: str,
    ) -> AdmissionDecision:
        decision, _ = self.reserve(
            record,
            base_decision,
            query_lane=query_lane,
        )
        return decision

    def snapshot(self) -> dict[str, Any]:
        return {
            "policy_version": WEEKLY_POLICY_VERSION,
            "reference_time": self.reference_time.isoformat(),
            "window_start": self.window_start.isoformat(),
            "maximum_admitted_candidates": (
                self.policy.maximum_admitted_candidates
            ),
            "admitted_unique": len(self._admitted_keys),
            "lane_counts": dict(sorted(self._lane_counts.items())),
            "deferred_reason_counts": dict(sorted(self._reason_counts.items())),
            "source_query_caps": dict(
                sorted(self.policy.source_query_caps.items())
            ),
            "query_caps": dict(sorted(self.policy.query_caps.items())),
        }
