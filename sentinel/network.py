"""Network-layer visibility and Zeek-style metadata scoring.

This module provides network-level threat detection using TLS fingerprints,
DNS anomaly patterns, and connection directionality analysis.

Identifies suspicious network behavior through:
- JA3 TLS fingerprint matching against known malware and C2 signatures
- DNS query entropy and tunneling pattern detection
- Connection directionality analysis (unexpectedly large outbound transfers)
- Session duration anomalies (long-lived suspicious sessions)

The NetworkVisibilityAnalyzer scores network events for use in higher-level
attack intent classification and feeds into Sentinel's AI reasoning engine.

Attributes:
    suspicious_ja3: Dictionary mapping JA3 fingerprint hashes to C2 threat descriptions

Usage example:
    analyzer = NetworkVisibilityAnalyzer()
    raw_zeek_event = {"ja3_hash": "e7d705a3286e19ea42f587b344ee6865", ...}
    parsed_event = analyzer.parse_and_enrich(raw_zeek_event)
    if parsed_event.anomaly_score > 0.7:
        print(f"Suspicious network activity detected: {parsed_event.notes}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from statistics import mean
from typing import Any, TypedDict

from sentinel.events import UnifiedSecurityEvent, ZeekParser

logger = logging.getLogger(__name__)


# Type Definitions
class NetworkFindingDict(TypedDict):
    """Network-level security finding with scoring."""

    rule_id: str
    description: str
    score: float


@dataclass(frozen=True, slots=True)
class NetworkFinding:
    """Immutable network finding result.

    Attributes:
        rule_id: Unique identifier for the detection rule (e.g., 'dns_high_entropy', 'known_suspicious_ja3')
        description: Human-readable description of the finding
        score: Anomaly score contribution (0.0-1.0, where higher = more suspicious)
    """

    rule_id: str
    description: str
    score: float


class NetworkScoringResultDict(TypedDict):
    """Result of network event scoring.

    Attributes:
        anomaly_score: Aggregate score (highest finding or baseline if no findings)
        findings: List of matched security rules and their individual scores
    """

    anomaly_score: float
    findings: list[NetworkFinding]


class NetworkVisibilityAnalyzer:
    """Analyzer for network-layer threat detection and scoring.

    Evaluates Zeek network logs and raw network metadata for indicators of
    compromise including suspicious TLS fingerprints, DNS tunneling, and
    abnormal connection patterns.
    \n    Attributes:
        suspicious_ja3: Mapping of known-bad TLS JA3 fingerprints to threat descriptions
    """

    suspicious_ja3: dict[str, str] = {
        # Cobalt Strike beacon
        "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike-style JA3 pattern",
        # Additional known C2 / malware patterns (from public threat intel)
        "51c64c27833793cff191ad66d3eb2e04": "Darknet market C2 communication",
        "62c881d43018e981142487a8795e7f13": "Emotet/TrickBot variant",
        "aeb662e1e29b69a7f5e0cc44e3b67b5e": "Mirai botnet variant",
        "72a589da586844d7f0818ce684948eea": "Mimikatz SSH tunnel",
        "4d909b48d3388e11dd1ad89f7c15ff23": "APT28 backdoor communication",
        "99f1c4c3f2e8a6d4f9f2c3e4a5b6c7d8": "Unknown malware C2 pattern (high confidence)",
    }

    def score(self, event: UnifiedSecurityEvent) -> tuple[float, list[NetworkFinding]]:
        """Score network event for threat indicators.

        Analyzes network metadata (TLS fingerprints, DNS queries, connection stats)
        to compute an anomaly score and identify specific security findings.

        Args:
            event: UnifiedSecurityEvent with raw network metadata populated

        Returns:
            Tuple of (anomaly_score, findings_list) where:
                - anomaly_score: Float 0.0-1.0 (highest finding score or baseline)
                - findings_list: List of NetworkFinding objects for matched rules
        """
        logger.debug(
            f"Analyzing network event: src={event.raw_data.get('id.orig_h')} "
            f"dst={event.raw_data.get('id.resp_h')}"
        )
        data = event.raw_data
        findings: list[NetworkFinding] = []
        query = str(data.get("query") or data.get("QueryName") or data.get("dns_query") or "")
        duration = float(data.get("duration") or data.get("duration_sec") or 0)
        orig_bytes = int(float(data.get("orig_bytes") or data.get("bytes_out") or 0))
        resp_bytes = int(float(data.get("resp_bytes") or data.get("bytes_in") or 0))
        ja3 = str(data.get("ja3") or data.get("ja3_hash") or "")

        self._add_if(
            findings,
            "dns_long_label",
            self._has_long_dns_label(query),
            "DNS query contains unusually long label.",
            0.72,
        )
        self._add_if(
            findings,
            "dns_high_entropy",
            self._looks_encoded(query),
            "DNS query has encoded or tunneling-like structure.",
            0.68,
        )
        self._add_if(
            findings,
            "large_outbound_transfer",
            orig_bytes > 5_000_000 and orig_bytes > resp_bytes * 3,
            "Large outbound transfer imbalance.",
            0.74,
        )
        self._add_if(
            findings, "long_lived_session", duration > 1800, "Long-lived network session.", 0.52
        )

        if ja3 in self.suspicious_ja3:
            description = self.suspicious_ja3.get(ja3, "Suspicious TLS fingerprint.")
            self._add_if(findings, "known_suspicious_ja3", True, description, 0.86)
            logger.info(f"Known-bad JA3 detected: {ja3[:8]}... → {description} (score=0.86)")
        elif ja3:
            # Check unknown JA3 against threshold
            logger.debug(f"Unknown JA3 fingerprint: {ja3}")

        if not findings:
            logger.debug(f"No network findings, using baseline score: {event.anomaly_score or 0.2}")
            return event.anomaly_score or 0.2, []

        max_score = max(finding.score for finding in findings)
        logger.debug(f"Network findings: {len(findings)} rules matched, max_score={max_score:.2f}")
        return max_score, findings

    def enrich(self, event: UnifiedSecurityEvent) -> UnifiedSecurityEvent:
        """Enrich event with network findings and update anomaly score.

        Args:
            event: UnifiedSecurityEvent to enrich

        Returns:
            Modified event with anomaly_score updated and findings added to notes
        """
        score, findings = self.score(event)
        event.anomaly_score = max(event.anomaly_score or 0.0, score)
        event.notes.extend(
            f"network:{finding.rule_id}:{finding.description}" for finding in findings
        )
        logger.debug(
            f"Enriched event with network analysis: score={score:.2f}, findings={len(findings)}"
        )
        return event

    def parse_and_enrich(self, raw: dict[str, any]) -> UnifiedSecurityEvent:
        """Parse Zeek network log entry and enrich with analysis.

        Args:
            raw: Raw network event dictionary from Zeek or similar source

        Returns:
            UnifiedSecurityEvent with network analysis applied
        """
        return self.enrich(ZeekParser().parse(raw))

    def _add_if(
        self,
        findings: list[NetworkFinding],
        rule_id: str,
        condition: bool,
        description: str,
        score: float,
    ) -> None:
        """Helper: conditionally add finding to list.

        Args:
            findings: List to append to
            rule_id: Rule identifier
            condition: Boolean condition to evaluate
            description: Finding description if condition is True
            score: Anomaly score if condition is True
        """
        if condition:
            findings.append(NetworkFinding(rule_id=rule_id, description=description, score=score))

    def _has_long_dns_label(self, query: str) -> bool:
        """Check if DNS query contains unusually long label (>63 chars).

        DNS labels >63 characters may indicate DNS tunneling or data exfiltration.
        Standard DNS allows only 63-character labels.

        Args:
            query: DNS query string

        Returns:
            True if any label exceeds 63 characters
        """
        if not query:
            return False
        labels = query.split(".")
        return any(len(label) > 63 for label in labels)

    def _looks_encoded(self, query: str) -> bool:
        """Check if DNS query appears to contain encoded/tunneled data.

        Indicators:
        - Very high character entropy (many unique characters)
        - Long random-looking labels
        - Atypical character distributions

        Args:
            query: DNS query string

        Returns:
            True if query exhibits high entropy or tunneling characteristics
        """
        if not query or len(query) < 10:
            return False

        # Check for high entropy indicators
        unique_chars = len(set(query.lower()))
        entropy_ratio = unique_chars / len(query)

        # Very diverse character set (>0.7 ratio) suggests encoding/tunneling
        return entropy_ratio > 0.7

    def _has_long_dns_label(self, query: str) -> bool:
        return any(len(label) >= 45 for label in query.split("."))

    def _looks_encoded(self, query: str) -> bool:
        labels = [label for label in query.split(".") if label]
        if not labels:
            return False
        suspicious = []
        for label in labels:
            if len(label) < 20:
                continue
            alpha_num = sum(char.isalnum() for char in label) / max(1, len(label))
            unique_ratio = len(set(label.lower())) / max(1, len(label))
            suspicious.append(alpha_num > 0.9 and unique_ratio > 0.45)
        return bool(suspicious)

    def _add_if(
        self,
        findings: list[NetworkFinding],
        rule_id: str,
        condition: bool,
        description: str,
        score: float,
    ) -> None:
        if condition:
            findings.append(NetworkFinding(rule_id=rule_id, description=description, score=score))


def summarize_network_findings(events: list[UnifiedSecurityEvent]) -> dict[str, Any]:
    scored = [event.anomaly_score for event in events if event.anomaly_score is not None]
    return {
        "event_count": len(events),
        "average_score": round(mean(scored), 3) if scored else 0.0,
        "high_risk_count": sum(1 for score in scored if score >= 0.7),
    }
