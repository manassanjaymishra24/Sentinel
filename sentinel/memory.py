"""Layer 3 situational memory and entity graph."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.events import UnifiedSecurityEvent


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    relationship: str
    weight: float = 1.0
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EntityGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str], GraphEdge] = {}

    def add_event(self, event: UnifiedSecurityEvent) -> None:
        source = event.entity_id or event.entity_name or "unknown"
        self.nodes.setdefault(source, {"type": event.entity_type, "name": event.entity_name})
        if not event.target_entity:
            return
        target = event.target_entity
        self.nodes.setdefault(target, {"type": "unknown", "name": target})
        key = (source, target, event.action)
        edge = self.edges.get(key)
        if edge is None:
            self.edges[key] = GraphEdge(source=source, target=target, relationship=event.action)
        else:
            edge.weight += 1.0
            edge.last_seen = event.timestamp

    def neighbors(self, entity_id: str) -> list[str]:
        return [edge.target for edge in self.edges.values() if edge.source == entity_id]

    def snapshot(self, limit: int = 25) -> dict[str, Any]:
        edges = sorted(self.edges.values(), key=lambda edge: edge.last_seen, reverse=True)[:limit]
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "recent_edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relationship": edge.relationship,
                    "weight": edge.weight,
                    "last_seen": edge.last_seen.isoformat(),
                }
                for edge in edges
            ],
        }


class SlidingContextWindow:
    def __init__(self, hours: int = 4) -> None:
        self.window = timedelta(hours=hours)
        self.events: deque[UnifiedSecurityEvent] = deque()
        self.by_entity: dict[str, list[UnifiedSecurityEvent]] = defaultdict(list)

    def add(self, event: UnifiedSecurityEvent) -> None:
        self.events.append(event)
        key = event.entity_id or event.entity_name or "unknown"
        self.by_entity[key].append(event)
        self.prune(now=event.timestamp)

    def prune(self, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        cutoff = now - self.window
        while self.events and self.events[0].timestamp < cutoff:
            expired = self.events.popleft()
            key = expired.entity_id or expired.entity_name or "unknown"
            self.by_entity[key] = [
                event for event in self.by_entity[key] if event.event_id != expired.event_id
            ]
            if not self.by_entity[key]:
                del self.by_entity[key]

    def recent(self) -> list[UnifiedSecurityEvent]:
        self.prune()
        return list(self.events)


@dataclass(slots=True)
class Hypothesis:
    suspected_attack_stage: str | None = None
    involved_entities: list[str] = field(default_factory=list)
    supporting_events: list[str] = field(default_factory=list)
    confidence: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class HypothesisStore:
    def __init__(self) -> None:
        self.current = Hypothesis()

    def update(
        self, stage: str | None, events: list[UnifiedSecurityEvent], confidence: float
    ) -> Hypothesis:
        entities = sorted({event.entity_id or event.entity_name or "unknown" for event in events})
        self.current = Hypothesis(
            suspected_attack_stage=stage,
            involved_entities=entities,
            supporting_events=[event.event_id for event in events],
            confidence=confidence,
            last_updated=datetime.now(timezone.utc),
        )
        return self.current


class ContextBuilder:
    def __init__(
        self,
        graph: EntityGraph,
        window: SlidingContextWindow,
        hypotheses: HypothesisStore,
    ) -> None:
        self.graph = graph
        self.window = window
        self.hypotheses = hypotheses

    def build(self) -> dict[str, Any]:
        events = self.window.recent()
        return {
            "events": [event.to_dict() for event in events],
            "entity_graph": self.graph.snapshot(),
            "hypothesis": {
                "suspected_attack_stage": self.hypotheses.current.suspected_attack_stage,
                "involved_entities": self.hypotheses.current.involved_entities,
                "supporting_events": self.hypotheses.current.supporting_events,
                "confidence": self.hypotheses.current.confidence,
                "last_updated": self.hypotheses.current.last_updated.isoformat(),
            },
        }


class SituationalMemory:
    def __init__(self, hours: int = 4) -> None:
        self.graph = EntityGraph()
        self.window = SlidingContextWindow(hours=hours)
        self.hypotheses = HypothesisStore()
        self.context_builder = ContextBuilder(self.graph, self.window, self.hypotheses)

    def add_event(self, event: UnifiedSecurityEvent) -> None:
        self.graph.add_event(event)
        self.window.add(event)
