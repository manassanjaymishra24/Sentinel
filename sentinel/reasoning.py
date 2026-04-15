"""Layer 4 intent reasoning engine.

The production design calls for LangGraph + LLM + Neo4j. This module keeps that
contract, but includes a deterministic in-memory reasoner for local development
and tests.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any


TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Command and Control",
    "Impact",
]


@dataclass(frozen=True, slots=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    keywords: tuple[str, ...]
    next_techniques: tuple[str, ...] = ()


DEFAULT_TECHNIQUES: dict[str, Technique] = {
    "T1059": Technique(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        ("powershell", "cmd", "bash", "sh", "script"),
        ("T1087", "T1105"),
    ),
    "T1105": Technique(
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
        ("download", "curl", "wget", "transfer"),
        ("T1005", "T1041"),
    ),
    "T1087": Technique(
        "T1087",
        "Account Discovery",
        "Discovery",
        ("net user", "whoami", "account", "ldap"),
        ("T1003", "T1021"),
    ),
    "T1003": Technique(
        "T1003",
        "OS Credential Dumping",
        "Credential Access",
        ("lsass", "mimikatz", "credential", "dump"),
        ("T1021", "T1041"),
    ),
    "T1021": Technique(
        "T1021",
        "Remote Services",
        "Lateral Movement",
        ("rdp", "ssh", "winrm", "remote"),
        ("T1005", "T1486"),
    ),
    "T1005": Technique(
        "T1005",
        "Data from Local System",
        "Collection",
        ("archive", "collect", "zip", "sensitive"),
        ("T1041",),
    ),
    "T1041": Technique(
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration",
        ("exfil", "upload", "large transfer"),
        ("T1486",),
    ),
    "T1486": Technique(
        "T1486", "Data Encrypted for Impact", "Impact", ("encrypt", "ransom", "shadowcopy"), ()
    ),
}


@dataclass(slots=True)
class TechniqueMatch:
    tactic: str
    technique_id: str
    technique_name: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Prediction:
    technique_id: str
    technique_name: str
    tactic: str
    probability: float
    impact_score: float


@dataclass(slots=True)
class ReasoningResult:
    attack_stage: str
    matched_techniques: list[TechniqueMatch]
    predicted_next: list[Prediction]
    confidence_score: float
    narrative_explanation: str
    recommended_actions: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_stage": self.attack_stage,
            "matched_techniques": [asdict(match) for match in self.matched_techniques],
            "predicted_next": [asdict(prediction) for prediction in self.predicted_next],
            "confidence_score": self.confidence_score,
            "narrative_explanation": self.narrative_explanation,
            "recommended_actions": self.recommended_actions,
        }


class InMemoryAttackGraph:
    def __init__(self, techniques: dict[str, Technique] | None = None) -> None:
        self.techniques = techniques or DEFAULT_TECHNIQUES

    def match(self, text: str) -> list[TechniqueMatch]:
        normalized = text.lower()
        matches: list[TechniqueMatch] = []
        for technique in self.techniques.values():
            evidence = [
                keyword
                for keyword in technique.keywords
                if self._keyword_present(keyword, normalized)
            ]
            if evidence:
                confidence = min(0.95, 0.45 + 0.15 * len(evidence))
                matches.append(
                    TechniqueMatch(
                        tactic=technique.tactic,
                        technique_id=technique.technique_id,
                        technique_name=technique.name,
                        confidence=confidence,
                        evidence=evidence,
                    )
                )
        return sorted(matches, key=lambda match: match.confidence, reverse=True)

    def _keyword_present(self, keyword: str, text: str) -> bool:
        if " " in keyword:
            return keyword in text
        return re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", text) is not None

    def predict_next(self, matches: list[TechniqueMatch]) -> list[Prediction]:
        scores: dict[str, float] = {}
        for match in matches:
            technique = self.techniques.get(match.technique_id)
            if not technique:
                continue
            for next_id in technique.next_techniques:
                scores[next_id] = max(scores.get(next_id, 0.0), match.confidence * 0.8)
        predictions = []
        for technique_id, score in sorted(scores.items(), key=lambda item: item[1], reverse=True)[
            :3
        ]:
            technique = self.techniques[technique_id]
            tactic_index = (
                TACTIC_ORDER.index(technique.tactic) if technique.tactic in TACTIC_ORDER else 0
            )
            predictions.append(
                Prediction(
                    technique_id=technique.technique_id,
                    technique_name=technique.name,
                    tactic=technique.tactic,
                    probability=round(score, 3),
                    impact_score=round(0.35 + tactic_index / (len(TACTIC_ORDER) * 1.4), 3),
                )
            )
        return predictions


class IntentReasoningEngine:
    def __init__(self, attack_graph: InMemoryAttackGraph | None = None) -> None:
        self.attack_graph = attack_graph or InMemoryAttackGraph()

    def analyze(self, context: dict[str, Any]) -> ReasoningResult:
        events = context.get("events", [])
        text = " ".join(
            " ".join(str(value) for value in event.values() if value is not None)
            for event in events
        )
        matches = self.attack_graph.match(text)
        predictions = self.attack_graph.predict_next(matches)
        attack_stage = self._stage_from_matches(matches)
        confidence = self._confidence(matches, events)
        narrative = self._narrate(attack_stage, matches, predictions, len(events))
        actions = self._recommend(confidence, predictions)
        return ReasoningResult(
            attack_stage=attack_stage,
            matched_techniques=matches,
            predicted_next=predictions,
            confidence_score=confidence,
            narrative_explanation=narrative,
            recommended_actions=actions,
        )

    def _stage_from_matches(self, matches: list[TechniqueMatch]) -> str:
        if not matches:
            return "Unknown"
        return max(
            matches,
            key=lambda match: (
                TACTIC_ORDER.index(match.tactic) if match.tactic in TACTIC_ORDER else -1
            ),
        ).tactic

    def _confidence(self, matches: list[TechniqueMatch], events: list[dict[str, Any]]) -> float:
        if not matches:
            return 0.15 if events else 0.0
        evidence_bonus = min(0.2, len(events) * 0.03)
        return round(
            min(
                0.98,
                sum(match.confidence for match in matches[:3]) / min(3, len(matches))
                + evidence_bonus,
            ),
            3,
        )

    def _narrate(
        self,
        stage: str,
        matches: list[TechniqueMatch],
        predictions: list[Prediction],
        event_count: int,
    ) -> str:
        if not matches:
            return f"{event_count} anomalous events were observed, but they do not map cleanly to the local ATT&CK knowledge base."
        observed = ", ".join(
            f"{match.technique_name} ({match.technique_id})" for match in matches[:3]
        )
        likely_next = (
            ", ".join(
                f"{prediction.technique_name} ({prediction.technique_id})"
                for prediction in predictions
            )
            or "no clear next step"
        )
        return f"{event_count} anomalous events suggest {observed}, placing the activity around {stage}. The most likely next techniques are {likely_next}."

    def _recommend(self, confidence: float, predictions: list[Prediction]) -> list[dict[str, Any]]:
        if confidence < 0.4:
            return [
                {
                    "action": "monitor",
                    "requires_human": False,
                    "rationale": "Confidence is below alert threshold.",
                }
            ]
        if confidence < 0.65:
            return [
                {
                    "action": "alert_analyst",
                    "requires_human": True,
                    "rationale": "Suspicious chain requires review.",
                }
            ]
        recommendations = [
            {
                "action": "preserve_forensics",
                "requires_human": False,
                "rationale": "Collect volatile context before it rolls off.",
            }
        ]
        if any(
            prediction.tactic in {"Lateral Movement", "Exfiltration", "Impact"}
            for prediction in predictions
        ):
            recommendations.append(
                {
                    "action": "isolate_candidate_host",
                    "requires_human": True,
                    "rationale": "Predicted next move has high operational impact.",
                }
            )
        if confidence >= 0.85 and any(
            prediction.tactic in {"Credential Access", "Impact"} for prediction in predictions
        ):
            recommendations.append(
                {
                    "action": "kill_suspicious_process",
                    "requires_human": True,
                    "rationale": "High-confidence endpoint compromise pattern.",
                }
            )
        return recommendations
