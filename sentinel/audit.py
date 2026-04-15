"""Explainability, audit trail, and analyst review support."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from sentinel.events import UnifiedSecurityEvent


@dataclass(slots=True)
class DecisionRecord:
    triggering_events: list[UnifiedSecurityEvent]
    anomaly_scores: list[float | None]
    classified_techniques: list[dict[str, Any]]
    narrative: str
    predicted_next: list[dict[str, Any]]
    recommended_actions: list[dict[str, Any]]
    action_taken: str
    confidence_score: float
    llm_reasoning_trace: str | None = None
    human_review_required: bool = False
    human_outcome: str | None = None
    decision_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp.isoformat(),
            "triggering_events": [event.to_dict() for event in self.triggering_events],
            "anomaly_scores": self.anomaly_scores,
            "classified_techniques": self.classified_techniques,
            "narrative": self.narrative,
            "predicted_next": self.predicted_next,
            "recommended_actions": self.recommended_actions,
            "action_taken": self.action_taken,
            "confidence_score": self.confidence_score,
            "llm_reasoning_trace": self.llm_reasoning_trace,
            "human_review_required": self.human_review_required,
            "human_outcome": self.human_outcome,
        }


class AuditTrail:
    def __init__(self) -> None:
        self.records: list[DecisionRecord] = []

    def append(self, record: DecisionRecord) -> None:
        self.records.append(record)

    def pending_review(self) -> list[DecisionRecord]:
        return [
            record
            for record in self.records
            if record.human_review_required and record.human_outcome is None
        ]


class ReportGenerator:
    def incident_markdown(self, record: DecisionRecord) -> str:
        techniques = (
            "\n".join(
                f"- {item.get('technique_id')}: {item.get('technique_name')} ({item.get('tactic')})"
                for item in record.classified_techniques
            )
            or "- None"
        )
        predictions = (
            "\n".join(
                f"- {item.get('technique_id')}: {item.get('technique_name')} probability={item.get('probability')}"
                for item in record.predicted_next
            )
            or "- None"
        )
        actions = (
            "\n".join(
                f"- {item.get('action')} human_required={item.get('requires_human')}: {item.get('rationale')}"
                for item in record.recommended_actions
            )
            or "- None"
        )
        return (
            f"# Sentinel Incident Report\n\n"
            f"- Decision ID: `{record.decision_id}`\n"
            f"- Timestamp: `{record.timestamp.isoformat()}`\n"
            f"- Confidence: `{record.confidence_score}`\n"
            f"- Action Taken: `{record.action_taken}`\n"
            f"- Human Review Required: `{record.human_review_required}`\n\n"
            f"## Narrative\n\n{record.narrative}\n\n"
            f"## Classified Techniques\n\n{techniques}\n\n"
            f"## Predicted Next Moves\n\n{predictions}\n\n"
            f"## Recommended Actions\n\n{actions}\n"
        )

    def write_incident_report(self, record: DecisionRecord, path: str | Path) -> Path:
        output = Path(path)
        output.write_text(self.incident_markdown(record), encoding="utf-8")
        return output

    def weekly_summary(self, records: list[DecisionRecord]) -> str:
        reviewed = sum(1 for record in records if record.human_outcome)
        average_confidence = sum(record.confidence_score for record in records) / max(
            1, len(records)
        )
        return (
            "# Sentinel Weekly Summary\n\n"
            f"- Decisions: {len(records)}\n"
            f"- Human-reviewed: {reviewed}\n"
            f"- Average confidence: {average_confidence:.2f}\n"
        )


class AnalystInterface:
    def __init__(self, audit_trail: AuditTrail) -> None:
        self.audit_trail = audit_trail

    def review(self, decision_id: str, outcome: str) -> DecisionRecord:
        allowed = {"approved", "rejected", "modified"}
        if outcome not in allowed:
            raise ValueError(f"outcome must be one of {sorted(allowed)}")
        for record in self.audit_trail.records:
            if record.decision_id == decision_id:
                record.human_outcome = outcome
                return record
        raise KeyError(decision_id)
