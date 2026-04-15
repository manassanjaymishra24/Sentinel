"""Layer 2 perception engine: behavioral baselines and anomaly scoring."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import log1p
from statistics import mean

from sentinel.events import UnifiedSecurityEvent


@dataclass(slots=True)
class EntityProfile:
    entity_id: str
    event_count: int = 0
    actions: Counter[str] = field(default_factory=Counter)
    targets: Counter[str] = field(default_factory=Counter)
    active_hours: Counter[int] = field(default_factory=Counter)
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def observe(self, event: UnifiedSecurityEvent) -> None:
        self.event_count += 1
        self.actions[event.action] += 1
        if event.target_entity:
            self.targets[event.target_entity] += 1
        self.active_hours[event.timestamp.hour] += 1
        self.updated_at = datetime.now(timezone.utc)


class BehavioralBaseline:
    def __init__(self) -> None:
        self._profiles: dict[str, EntityProfile] = {}

    def fit(self, events: list[UnifiedSecurityEvent]) -> None:
        for event in events:
            self.observe(event)

    def observe(self, event: UnifiedSecurityEvent) -> None:
        key = event.entity_id or event.entity_name or "unknown"
        self._profiles.setdefault(key, EntityProfile(entity_id=key)).observe(event)

    def score(self, event: UnifiedSecurityEvent) -> float:
        key = event.entity_id or event.entity_name or "unknown"
        profile = self._profiles.get(key)
        if profile is None or profile.event_count < 3:
            return 0.55

        action_rarity = 1.0 - (profile.actions[event.action] / profile.event_count)
        target_rarity = 0.0
        if event.target_entity:
            target_rarity = 1.0 - (
                profile.targets[event.target_entity] / max(1, sum(profile.targets.values()))
            )
        hour_rarity = 1.0 - (profile.active_hours[event.timestamp.hour] / profile.event_count)
        volume_pressure = min(0.2, log1p(profile.event_count) / 50)
        return max(
            0.0, min(1.0, mean([action_rarity, target_rarity, hour_rarity]) + volume_pressure)
        )

    def score_and_update(self, event: UnifiedSecurityEvent) -> UnifiedSecurityEvent:
        event.anomaly_score = self.score(event)
        self.observe(event)
        return event


class DriftDetector:
    def __init__(self, threshold: float = 0.25) -> None:
        self.threshold = threshold
        self._weekly_action_mix: list[Counter[str]] = []

    def record_week(self, events: list[UnifiedSecurityEvent]) -> None:
        self._weekly_action_mix.append(Counter(event.action for event in events))
        self._weekly_action_mix = self._weekly_action_mix[-8:]

    def is_drifting(self) -> bool:
        if len(self._weekly_action_mix) < 2:
            return False
        current = self._weekly_action_mix[-1]
        previous = self._weekly_action_mix[-2]
        all_actions = set(current) | set(previous)
        current_total = max(1, sum(current.values()))
        previous_total = max(1, sum(previous.values()))
        distance = (
            sum(abs(current[a] / current_total - previous[a] / previous_total) for a in all_actions)
            / 2
        )
        return distance > self.threshold


class PerceptionEngine:
    def __init__(self, threshold: float = 0.4) -> None:
        self.baseline = BehavioralBaseline()
        self.threshold = threshold

    def train(self, normal_events: list[UnifiedSecurityEvent]) -> None:
        self.baseline.fit(normal_events)

    def process(self, event: UnifiedSecurityEvent) -> UnifiedSecurityEvent | None:
        scored = self.baseline.score_and_update(event)
        if scored.anomaly_score is not None and scored.anomaly_score > self.threshold:
            return scored
        return None
