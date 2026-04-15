"""Long-term behavioral drift detection for security entities.

This module detects behavioral changes in entities over time windows, enabling
proactive threat hunting and advanced persistent threat (APT) identification.

Behavioral drift analysis compares entity activity across time periods using multiple
signals (incident frequency, confidence scores, MITRE techniques) to identify:
- Sudden escalations (frequency spikes, confidence changes)
- Tactical shifts (new MITRE techniques appearing)
- Emerging threats that deviate from baseline patterns

Attributes:
    DRIFT_THRESHOLD: Default threshold for anomaly classification

Usage example:
    store = IncidentStore('incidents.sqlite3')
    analyzer = BehavioralDriftAnalyzer(store)
    drift_result = analyzer.analyze_drift('host-0', window_size_days=7, num_windows=4)
    if drift_result['overall_drift_score'] > 0.5:
        print(f"Detected behavioral drift: {drift_result['anomalies']}")
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from statistics import mean, stdev
from typing import Any, Literal, TypedDict

from sentinel.storage import IncidentStore

logger = logging.getLogger(__name__)


# Type Definitions
class WindowProfile(TypedDict):
    """Behavioral profile of an entity within a time window."""

    period_start: str
    period_end: str
    incident_count: int
    avg_confidence: float
    max_confidence: float
    top_techniques: list[str]  # Top 3 MITRE technique IDs in period


class DriftAnomaly(TypedDict):
    """Detected behavioral anomaly within a time window."""

    type: Literal["frequency_spike", "confidence_change", "new_techniques"]
    severity: Literal["low", "medium", "high"]
    details: dict[str, Any]


class DriftResultDict(TypedDict):
    """Complete drift analysis result for an entity."""

    entity_key: str
    windows_analyzed: int
    window_size_days: int
    latest_window: WindowProfile | None
    frequency_drift: float
    confidence_drift: float
    technique_drift: float
    overall_drift_score: float
    anomalies: list[DriftAnomaly]


DRIFT_THRESHOLD: float = 0.6  # Default threshold for significant drift


class BehavioralDriftAnalyzer:
    def __init__(self, store: IncidentStore) -> None:
        """Initialize behavioral drift analyzer.

        Args:
            store: IncidentStore instance for querying historical incidents
        """
        self.store = store
        logger.debug(f"Initialized BehavioralDriftAnalyzer with store at {store.path}")

    def analyze_drift(
        self,
        entity_key: str,
        window_size_days: int = 7,
        num_windows: int = 4,
    ) -> DriftResultDict:
        """Analyze behavioral drift across multiple time windows.

        Compares entity behavior across consecutive time periods to detect:
        - Sudden changes in incident frequency (spikes)
        - Escalations in confidence scores
        - Tactical shifts (new MITRE techniques)

        Args:
            entity_key: Entity identifier to analyze
            window_size_days: Size of each time window in days (default: 7 = weekly)
            num_windows: Number of historical windows to analyze (default: 4 = monthly lookback)

        Returns:
            DriftResultDict with metrics and detected anomalies

        Note:
            Requires at least 2 windows of data. Returns zero drift if insufficient history.
            Uses coefficient of variation for frequency/confidence drift (normalized variance).
            Uses Jaccard similarity (1 - overlap) for technique drift.
        """
        logger.info(
            f"Analyzing drift for entity={entity_key} (window_size={window_size_days}d, num_windows={num_windows})"
        )
        windows = self._get_time_windows(window_size_days, num_windows)
        window_profiles = [self._profile_window(entity_key, start, end) for start, end in windows]

        # Compute drift metrics
        drift_metrics = {
            "entity_key": entity_key,
            "windows_analyzed": len(window_profiles),
            "window_size_days": window_size_days,
            "latest_window": window_profiles[-1] if window_profiles else None,
            "frequency_drift": 0.0,
            "confidence_drift": 0.0,
            "technique_drift": 0.0,
            "overall_drift_score": 0.0,
            "anomalies": [],
        }

        if len(window_profiles) < 2:
            logger.warning(
                f"Insufficient data for drift analysis: entity={entity_key} (only {len(window_profiles)} windows)"
            )
            return drift_metrics

        # Compute frequency drift (incidents per window)
        frequencies = [p["incident_count"] for p in window_profiles]
        if len(frequencies) >= 2 and max(frequencies) > 0:
            freq_variance = self._compute_variance(frequencies)
            drift_metrics["frequency_drift"] = round(freq_variance, 3)
            if freq_variance > 0.8:  # High variance = high drift
                anomaly: DriftAnomaly = {
                    "type": "frequency_spike",
                    "severity": "high" if freq_variance > 0.95 else "medium",
                    "details": {
                        "current": frequencies[-1],
                        "historical_avg": round(mean(frequencies[:-1]), 1),
                    },
                }
                drift_metrics["anomalies"].append(anomaly)
                logger.info(
                    f"Anomaly detected: frequency_spike [{anomaly['severity']}] for entity={entity_key}"
                )

        # Compute confidence drift
        confidences = [p["avg_confidence"] for p in window_profiles]
        if len(confidences) >= 2:
            conf_variance = self._compute_variance(confidences)
            drift_metrics["confidence_drift"] = round(conf_variance, 3)
            if conf_variance > 0.6:
                current_conf = confidences[-1]
                historical_avg = mean(confidences[:-1])
                severity: Literal["low", "medium", "high"] = (
                    "high" if abs(current_conf - historical_avg) > 0.4 else "medium"
                )
                anomaly: DriftAnomaly = {
                    "type": "confidence_change",
                    "severity": severity,
                    "details": {
                        "current": round(current_conf, 3),
                        "historical_avg": round(historical_avg, 3),
                    },
                }
                drift_metrics["anomalies"].append(anomaly)
                logger.info(
                    f"Anomaly detected: confidence_change [{severity}] for entity={entity_key}"
                )

        # Compute technique drift (Jaccard similarity)
        recent_techniques = set(window_profiles[-1]["top_techniques"])
        historical_techniques = set()
        for profile in window_profiles[:-1]:
            historical_techniques.update(profile["top_techniques"])

        if recent_techniques or historical_techniques:
            technique_overlap = len(recent_techniques & historical_techniques)
            technique_union = len(recent_techniques | historical_techniques)
            jaccard_similarity = technique_overlap / max(1, technique_union)
            technique_drift = 1.0 - jaccard_similarity  # Higher = more drift
            drift_metrics["technique_drift"] = round(technique_drift, 3)

            if technique_drift > 0.5:
                new_techniques = recent_techniques - historical_techniques
                anomaly: DriftAnomaly = {
                    "type": "new_techniques",
                    "severity": "high" if len(new_techniques) > 3 else "medium",
                    "details": {
                        "new_techniques": list(new_techniques),
                        "new_technique_count": len(new_techniques),
                    },
                }
                drift_metrics["anomalies"].append(anomaly)
                logger.info(
                    f"Anomaly detected: new_techniques [{anomaly['severity']}] for entity={entity_key}"
                )

        # Compute overall drift score
        drift_scores = [
            drift_metrics["frequency_drift"],
            drift_metrics["confidence_drift"],
            drift_metrics["technique_drift"],
        ]
        drift_metrics["overall_drift_score"] = round(mean(drift_scores), 3)

        if drift_metrics["overall_drift_score"] > DRIFT_THRESHOLD:
            logger.warning(
                f"High drift detected: entity={entity_key} score={drift_metrics['overall_drift_score']:.2f} (threshold={DRIFT_THRESHOLD})"
            )
        else:
            logger.info(
                f"Drift analysis: entity={entity_key} windows={len(window_profiles)} drift_score={drift_metrics['overall_drift_score']:.2f}"
            )

        return drift_metrics

    def _get_time_windows(self, window_size_days: int, num_windows: int) -> list[tuple[str, str]]:
        """Generate time windows from oldest to most recent.

        Args:
            window_size_days: Duration of each window in days
            num_windows: Number of windows to generate

        Returns:
            List of (start_iso, end_iso) tuples, oldest first
        """
        logger.debug(f"Generating {num_windows} time windows of {window_size_days} days each")
        now = datetime.now(timezone.utc)
        windows = []
        for i in range(num_windows - 1, -1, -1):
            end = now - timedelta(days=i * window_size_days)
            start = end - timedelta(days=window_size_days)
            windows.append((start.isoformat(), end.isoformat()))
        return windows

    def _profile_window(self, entity_key: str, start: str, end: str) -> WindowProfile:
        """Build a behavioral profile for a time window.

        Args:
            entity_key: Entity to profile
            start: Start of window (ISO format)
            end: End of window (ISO format)

        Returns:
            WindowProfile with incident statistics for the period
        """
        with self.store._connect() as conn:
            rows = conn.execute(
                """
                SELECT confidence, record_json FROM incidents
                WHERE entity_keys LIKE ? AND timestamp >= ? AND timestamp <= ?
                """,
                (f"%{entity_key}%", start, end),
            ).fetchall()

        if not rows:
            return {
                "period_start": start,
                "period_end": end,
                "incident_count": 0,
                "avg_confidence": 0.0,
                "top_techniques": [],
            }

        # Extract data
        confidences = [row[0] for row in rows]
        all_techniques = []

        for row in rows:
            record = json.loads(row[1])
            for tech in record.get("classified_techniques", []):
                all_techniques.append(tech.get("technique_id", "unknown"))

        # Compute top techniques (top 5)
        technique_counts = Counter(all_techniques)
        top_techniques = [tech for tech, count in technique_counts.most_common(5)]

        return {
            "period_start": start,
            "period_end": end,
            "incident_count": len(rows),
            "avg_confidence": round(mean(confidences), 3) if confidences else 0.0,
            "top_techniques": top_techniques,
        }

    def _compute_variance(self, values: list[float]) -> float:
        """Compute coefficient of variation (normalized std dev)."""
        if len(values) < 2 or max(values) == 0:
            return 0.0
        try:
            std = stdev(values)
            avg = mean(values)
            return std / max(0.01, avg)  # Avoid division by zero
        except (ValueError, ZeroDivisionError):
            return 0.0

    def detect_all_drifting_entities(
        self,
        drift_threshold: float = DRIFT_THRESHOLD,
        window_size_days: int = 7,
        num_windows: int = 4,
    ) -> list[DriftResultDict]:
        """Find all entities showing significant behavioral drift.

        Scans top entities for anomalous behavioral changes that may indicate
        compromise or attack escalation.

        Args:
            drift_threshold: Minimum drift score to be considered drifting (default: 0.6)
            window_size_days: Size of each time window (default: 7)
            num_windows: Number of windows to analyze (default: 4)

        Returns:
            List of DriftResultDict for drifting entities, sorted by drift score (highest first)
        """
        logger.info(f"Scanning for drifting entities (threshold={drift_threshold})")
        # Get all entities
        top_entities = self.store.get_top_entities(limit=100)
        drifting_entities: list[DriftResultDict] = []

        for entity_data in top_entities:
            drift_result = self.analyze_drift(
                entity_data["entity_key"],
                window_size_days=window_size_days,
                num_windows=num_windows,
            )

            if drift_result["overall_drift_score"] > drift_threshold:
                drifting_entities.append(drift_result)

        # Sort by drift score (descending)
        drifting_entities.sort(key=lambda x: x["overall_drift_score"], reverse=True)
        logger.info(f"Found {len(drifting_entities)} drifting entities")
        return drifting_entities
