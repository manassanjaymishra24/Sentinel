"""Persistent SQLite incident store with rich query and reputation analysis.

This module provides long-term incident storage and analysis capabilities within Sentinel:
- Persistent SQLite database for audit trail and incident history
- Rich query interfaces (by entity, stage, confidence, similarity) for threat hunting
- Entity reputation scoring with multi-factor algorithm for prioritization
- Behavioral analysis support for threat pattern recognition and drift detection

The IncidentStore is the system of record for all security decisions and human reviews,
enabling investigation, compliance, and machine learning feedback loops.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any, Literal, TypedDict

from sentinel.audit import DecisionRecord

logger = logging.getLogger(__name__)


# Type Definitions
class EntityStatisticsDict(TypedDict):
    """Statistics summary for a security entity."""
    entity_key: str
    total_incidents: int
    avg_confidence: float
    max_confidence: float
    min_confidence: float
    reviewed_count: int
    pending_review: int


class EntityActivityDict(TypedDict):
    """Entity activity metrics for leaderboards."""
    entity_key: str
    incident_count: int
    avg_confidence: float


class ReputationFactorsDict(TypedDict):
    """Factors contributing to entity reputation score."""
    incident_frequency: float
    avg_confidence: float
    recency_weight: float
    false_positive_rate: float
    fp_penalty: float


class ReputationResultDict(TypedDict):
    """Entity reputation assessment result."""
    entity_key: str
    reputation_score: float
    risk_level: Literal["clean", "low", "medium", "high"]
    incidents_in_period: int
    factors: ReputationFactorsDict


class IncidentRecordDict(TypedDict):
    """Minimal incident summary for queries."""
    decision_id: str
    timestamp: str
    entity_keys: list[str]
    attack_stage: str | None
    confidence: float
    human_review_required: bool
    human_outcome: str | None
    record_json: dict[str, Any]
    overlap_score: float | None  # Used in similarity queries


class IncidentStore:
    """Persistent SQLite store for security incident records and approvals.
    
    Provides ACID compliance for incident tracking, approval workflows,
    and historical analysis. Supports rich queries for threat hunting
    and reputation-based entity assessment.
    
    Attributes:
        path: SQLite database file path
    """

    def __init__(self, path: str | Path = "sentinel_data/incidents.sqlite3") -> None:
        """Initialize incident store with SQLite backend.
        
        Args:
            path: Database file path (created if doesn't exist)
        """
        self.path = Path(path)
        if self.path.parent:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Initializing IncidentStore at {self.path}")
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        """Create SQLite connection with Row factory.
        
        Returns:
            sqlite3.Connection with Row factory for dict-like row access
        """
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Initialize database schema with incidents and approvals tables."""
        logger.debug("Initializing database schema")
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    decision_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    entity_keys TEXT NOT NULL,
                    attack_stage TEXT,
                    confidence REAL NOT NULL,
                    human_review_required INTEGER NOT NULL,
                    human_outcome TEXT,
                    record_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    actor TEXT,
                    details_json TEXT NOT NULL
                )
                """
            )
            logger.debug("Schema initialized successfully")

    def save_decision(self, record: DecisionRecord) -> None:
        """Persist decision record to incident table.
        
        Args:
            record: DecisionRecord to store (becomes incident)
        """
        logger.debug(f"Saving decision: {record.decision_id}")
        entity_keys = sorted(
            {
                event.entity_id or event.entity_name or "unknown"
                for event in record.triggering_events
            }
        )
        attack_stage = None
        if record.classified_techniques:
            attack_stage = record.classified_techniques[0].get("tactic")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents
                (decision_id, timestamp, entity_keys, attack_stage, confidence, human_review_required, human_outcome, record_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.decision_id,
                    record.timestamp.isoformat(),
                    json.dumps(entity_keys),
                    attack_stage,
                    record.confidence_score,
                    int(record.human_review_required),
                    record.human_outcome,
                    json.dumps(record.to_dict(), default=str),
                ),
            )
        logger.info(f"Saved incident {record.decision_id}: entities={entity_keys}, stage={attack_stage}, confidence={record.confidence_score:.2f}")

    def record_approval(self, decision_id: str, outcome: str, actor: str | None = None, details: dict[str, Any] | None = None) -> None:
        """Record human approval/review decision for incident.
        
        Args:
            decision_id: Decision ID being reviewed
            outcome: Approval outcome (e.g., 'approved', 'false_positive', 'investigate')
            actor: User or system that made the decision
            details: Additional structured data about the approval
        """
        logger.info(f"Recording approval for {decision_id}: outcome={outcome}, actor={actor}")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals (decision_id, timestamp, outcome, actor, details_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    datetime.now(timezone.utc).isoformat(),
                    outcome,
                    actor,
                    json.dumps(details or {}),
                ),
            )
            conn.execute("UPDATE incidents SET human_outcome = ? WHERE decision_id = ?", (outcome, decision_id))

    def recent_incidents(self, limit: int = 10) -> list[IncidentRecordDict]:
        """Get most recent incidents (newest first).
        
        Args:
            limit: Maximum number of incidents to return (default: 10)
            
        Returns:
            List of incident records ordered by timestamp (most recent first)
        """
        logger.debug(f"Querying recent incidents (limit={limit})")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        logger.debug(f"Found {len(rows)} recent incidents")
        return [self._row_to_dict(row) for row in rows]

    def similar_incidents(self, entity_key: str, limit: int = 5) -> list[IncidentRecordDict]:
        """Get incidents for specific entity (simple substring match).
        
        Args:
            entity_key: Entity identifier to match (host, user, etc.)
            limit: Maximum results (default: 5)
            
        Returns:
            List of incidents for entity ordered by timestamp (most recent first)
        """
        logger.debug(f"Querying incidents for entity: {entity_key}")
        needle = f"%{entity_key}%"
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE entity_keys LIKE ? ORDER BY timestamp DESC LIMIT ?",
                (needle, limit),
            ).fetchall()
        logger.debug(f"Found {len(rows)} incidents for entity {entity_key}")
        return [self._row_to_dict(row) for row in rows]

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert SQLite Row to dictionary with JSON fields parsed.
        
        Args:
            row: SQLite Row object
            
        Returns:
            Dictionary with entity_keys and record_json deserialized
        """
        data = dict(row)
        data["entity_keys"] = json.loads(data["entity_keys"])
        data["record_json"] = json.loads(data["record_json"])
        return data

    def get_incidents_by_entity(self, entity_key: str, limit: int = 20) -> list[IncidentRecordDict]:
        """Get all incidents for a specific entity.
        
        Queries the incident history by entity key to support threat hunting,
        timeline reconstruction, and reputation estimation.
        
        Args:
            entity_key: Entity identifier (host, user, etc.)
            limit: Maximum incidents to return (default: 20)
            
        Returns:
            List of incident records for entity, ordered by timestamp (most recent first)
        """
        logger.debug(f"Querying incidents by entity: {entity_key} (limit={limit})")
        needle = f'"{{entity_key}}"'
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE entity_keys LIKE ? ORDER BY timestamp DESC LIMIT ?",
                (f"%{entity_key}%", limit),
            ).fetchall()
        logger.debug(f"Found {len(rows)} incidents for entity {entity_key}")
        return [self._row_to_dict(row) for row in rows]

    def get_incidents_by_stage(self, attack_stage: str, limit: int = 20) -> list[IncidentRecordDict]:
        """Get all incidents for a specific attack stage (MITRE tactic).
        
        Supports tactical-level analysis and attack pattern identification.
        
        Args:
            attack_stage: MITRE tactic name (e.g., 'Reconnaissance', 'Lateral Movement')
            limit: Maximum incidents to return (default: 20)
            
        Returns:
            List of incidents with matching attack stage, ordered by timestamp
        """
        logger.debug(f"Querying incidents by stage: {attack_stage} (limit={limit})")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE attack_stage = ? ORDER BY timestamp DESC LIMIT ?",
                (attack_stage, limit),
            ).fetchall()
        logger.debug(f"Found {len(rows)} incidents for stage {attack_stage}")
        return [self._row_to_dict(row) for row in rows]

    def get_incidents_by_confidence(self, min_confidence: float, limit: int = 20) -> list[IncidentRecordDict]:
        """Get incidents with confidence >= min_confidence threshold.
        
        Filters incidents by decision confidence to prioritize high-confidence detections.
        
        Args:
            min_confidence: Minimum confidence score (0.0-1.0 scale)
            limit: Maximum incidents to return (default: 20)
            
        Returns:
            List of incidents meeting confidence threshold, sorted by confidence (highest first)
        """
        logger.debug(f"Querying incidents by confidence: >={min_confidence:.2f} (limit={limit})")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE confidence >= ? ORDER BY confidence DESC, timestamp DESC LIMIT ?",
                (min_confidence, limit),
            ).fetchall()
        logger.debug(f"Found {len(rows)} incidents with confidence >= {min_confidence:.2f}")
        return [self._row_to_dict(row) for row in rows]

    def find_similar_incidents(self, decision_id: str, limit: int = 5) -> list[IncidentRecordDict]:
        """Find incidents with overlapping techniques or entities.
        
        Computes overlap scores based on:
        - Entity overlap (1 point per shared entity)
        - Technique overlap (2 points per shared MITRE technique)
        
        Args:
            decision_id: Reference incident ID
            limit: Maximum similar incidents to return
            
        Returns:
            List of similar incidents sorted by overlap score (descending)
        """
        logger.debug(f"Finding similar incidents for {decision_id}")
        with self._connect() as conn:
            # Get the reference incident
            ref_row = conn.execute(
                "SELECT * FROM incidents WHERE decision_id = ?",
                (decision_id,),
            ).fetchone()
        
        if not ref_row:
            logger.warning(f"Reference incident not found: {decision_id}")
            return []
        
        ref_data = self._row_to_dict(ref_row)
        ref_entities = set(ref_data["entity_keys"])
        ref_techniques = {
            t.get("technique_id") for t in ref_data["record_json"].get("classified_techniques", [])
        }
        logger.debug(f"Reference: entities={ref_entities}, techniques={ref_techniques}")
        
        # Find incidents with overlapping entities or techniques
        candidates = []
        with self._connect() as conn:
            all_incidents = conn.execute(
                "SELECT * FROM incidents WHERE decision_id != ? ORDER BY timestamp DESC",
                (decision_id,),
            ).fetchall()
        
        for row in all_incidents:
            incident = self._row_to_dict(row)
            incident_entities = set(incident["entity_keys"])
            incident_techniques = {
                t.get("technique_id") for t in incident["record_json"].get("classified_techniques", [])
            }
            
            # Compute overlap score
            entity_overlap = len(ref_entities & incident_entities)
            technique_overlap = len(ref_techniques & incident_techniques)
            overlap_score = entity_overlap + (technique_overlap * 2)  # Weight techniques higher
            
            if overlap_score > 0:
                incident["overlap_score"] = overlap_score
                candidates.append(incident)
        
        # Sort by overlap score and return top matches
        candidates.sort(key=lambda x: x["overlap_score"], reverse=True)
        logger.debug(f"Found {len(candidates[:limit])} similar incidents (top {min(len(candidates), limit)} of {len(candidates)} candidates)")
        return candidates[:limit]

    def get_entity_statistics(self, entity_key: str) -> EntityStatisticsDict:
        """Get statistics for an entity (incident count, confidence, etc.).
        
        Provides aggregate statistics across all incidents for an entity,
        including review status and confidence distribution.
        
        Args:
            entity_key: Entity identifier
            
        Returns:
            Dictionary with keys:
                - entity_key: The queried entity
                - total_incidents: Total incident count
                - avg_confidence: Average confidence score
                - max_confidence: Highest confidence score
                - min_confidence: Lowest confidence score
                - reviewed_count: Incidents with human review
                - pending_review: Incidents awaiting review
        """
        logger.debug(f"Computing statistics for entity: {entity_key}")
        with self._connect() as conn:
            stats = conn.execute(
                """
                SELECT 
                    COUNT(*) as total_incidents,
                    AVG(confidence) as avg_confidence,
                    MAX(confidence) as max_confidence,
                    MIN(confidence) as min_confidence,
                    SUM(CASE WHEN human_outcome IS NOT NULL THEN 1 ELSE 0 END) as reviewed_count
                FROM incidents 
                WHERE entity_keys LIKE ?
                """,
                (f"%{entity_key}%",),
            ).fetchone()
        
        if not stats:
            logger.debug(f"No statistics found for entity: {entity_key}")
            return {}
        
        result = {
            "entity_key": entity_key,
            "total_incidents": stats[0] or 0,
            "avg_confidence": round(stats[1], 3) if stats[1] else 0.0,
            "max_confidence": round(stats[2], 3) if stats[2] else 0.0,
            "min_confidence": round(stats[3], 3) if stats[3] else 0.0,
            "reviewed_count": stats[4] or 0,
            "pending_review": (stats[0] or 0) - (stats[4] or 0),
        }
        logger.debug(f"Entity {entity_key} stats: {result['total_incidents']} incidents, {result['reviewed_count']} reviewed")
        return result

    def get_top_entities(self, limit: int = 10) -> list[EntityActivityDict]:
        """Get entities with most incidents (activity leaderboard).
        
        Args:
            limit: Maximum entities to return
            
        Returns:
            List of entities with incident counts, sorted by activity (most active first)
        """
        logger.debug(f"Querying top {limit} entities by incident count")
        with self._connect() as conn:
            # This is a simplified version; a full implementation might use JSON aggregation
            rows = conn.execute(
                """
                SELECT entity_keys, COUNT(*) as incident_count, AVG(confidence) as avg_confidence
                FROM incidents
                GROUP BY entity_keys
                ORDER BY incident_count DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        
        results = []
        for row in rows:
            entities = json.loads(row[0])
            for entity in entities:
                results.append({
                    "entity_key": entity,
                    "incident_count": row[1],
                    "avg_confidence": round(row[2], 3) if row[2] else 0.0,
                })
        
        # Sort by incident count
        results.sort(key=lambda x: x["incident_count"], reverse=True)
        logger.debug(f"Found {len(results[:limit])} top entities")
        return results[:limit]

    def compute_entity_reputation(
        self,
        entity_key: str,
        days_lookback: int = 30,
        recency_weight: float = 0.3,
    ) -> ReputationResultDict:
        """
        Compute a reputation score for an entity (0-1 scale).
        Higher = more suspicious.
        
        Factors:
        - Incident frequency (normalized by days)
        - Confidence scores (higher avg = worse)
        - Recent activity (time decay: recent = more weight)
        - Approval outcomes (false positives reduce score)
        """
        lookback_date = (datetime.now(timezone.utc) - timedelta(days=days_lookback)).isoformat()
        
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT timestamp, confidence, human_outcome FROM incidents
                WHERE entity_keys LIKE ? AND timestamp > ?
                ORDER BY timestamp DESC
                """,
                (f"%{entity_key}%", lookback_date),
            ).fetchall()
        
        if not rows:
            return {
                "entity_key": entity_key,
                "reputation_score": 0.0,
                "risk_level": "clean",
                "incidents_in_period": 0,
                "factors": {},
            }
        
        now = datetime.now(timezone.utc)
        
        # Factor 1: Incident frequency (incidents per day)
        incidents_in_period = len(rows)
        incident_frequency = incidents_in_period / max(1, days_lookback)
        freq_score = min(0.5, incident_frequency * 0.2)  # Capped at 0.5
        
        # Factor 2: Average confidence in this period
        confidence_scores = [row[1] for row in rows]
        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        conf_score = avg_confidence * 0.4
        
        # Factor 3: Recency (give more weight to recent incidents)
        recency_scores = []
        for row in rows:
            incident_time = datetime.fromisoformat(row[0].replace('Z', '+00:00'))
            age_days = (now - incident_time).days
            # Linear decay: 0 days old = 1.0, 30+ days old = 0.0
            recency = max(0, 1.0 - (age_days / max(1, days_lookback)))
            recency_scores.append(recency)
        avg_recency = sum(recency_scores) / len(recency_scores)
        recency_score = avg_recency * recency_weight
        
        # Factor 4: False positive rate (reduce score if many false alarm outcomes)
        false_positives = sum(1 for row in rows if row[2] and "false" in str(row[2]).lower())
        false_positive_rate = false_positives / len(rows)
        fp_penalty = false_positive_rate * 0.2
        
        # Compute final reputation score (0-1)
        reputation_score = min(1.0, max(0.0, freq_score + conf_score + recency_score - fp_penalty))
        
        # Determine risk level
        if reputation_score < 0.2:
            risk_level = "clean"
        elif reputation_score < 0.5:
            risk_level = "low"
        elif reputation_score < 0.7:
            risk_level = "medium"
        else:
            risk_level = "high"
        
        return {
            "entity_key": entity_key,
            "reputation_score": round(reputation_score, 3),
            "risk_level": risk_level,
            "incidents_in_period": incidents_in_period,
            "factors": {
                "incident_frequency": round(freq_score, 3),
                "avg_confidence": round(conf_score, 3),
                "recency_weight": round(recency_score, 3),
                "false_positive_rate": round(false_positive_rate, 3),
                "fp_penalty": round(fp_penalty, 3),
            },
        }

    def get_entity_reputation_leaderboard(self, limit: int = 20, days_lookback: int = 30) -> list[ReputationResultDict]:
        """Get top riskiest entities by reputation score."""
        top_entities = self.get_top_entities(limit=limit * 2)  # Get 2x to account for some being clean
        
        results = []
        for entity_data in top_entities:
            rep = self.compute_entity_reputation(entity_data["entity_key"], days_lookback=days_lookback)
            if rep["reputation_score"] > 0.1:  # Filter out clean entities
                results.append(rep)
        
        # Sort by reputation score (descending = riskiest first)
        results.sort(key=lambda x: x["reputation_score"], reverse=True)
        return results[:limit]

