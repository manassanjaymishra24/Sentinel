"""Demo of all new features working together."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile

from sentinel.audit import DecisionRecord
from sentinel.drift import BehavioralDriftAnalyzer
from sentinel.events import UnifiedSecurityEvent
from sentinel.llm import MockLLMProvider, SafetyEnvelopeReasoner
from sentinel.network import NetworkVisibilityAnalyzer
from sentinel.storage import IncidentStore


def demo_token_budgeting_and_caching():
    """Demo: Token budgeting and response caching."""
    print("\n" + "=" * 70)
    print("DEMO 1: Token Budgeting + Response Caching")
    print("=" * 70)
    
    mock_output = {
        "attack_stage": "Execution",
        "matched_techniques": [
            {
                "tactic": "Execution",
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "confidence": 0.8,
                "evidence": ["powershell.exe"],
            }
        ],
        "predicted_next": [],
        "confidence_score": 0.55,
        "narrative_explanation": "Suspicious PowerShell execution detected",
        "recommended_actions": [
            {"action": "preserve_forensics", "requires_human": False}
        ],
    }
    
    reasoner = SafetyEnvelopeReasoner(
        provider=MockLLMProvider(mock_output),
        max_tokens_per_session=2000,
        enable_response_cache=True,
        lower_threshold=0.0,
        upper_threshold=1.0,
    )
    
    context = {
        "events": [
            {"ProcessName": "powershell.exe", "CommandLine": "Write-Host test"}
        ]
    }
    
    # First call - hits LLM, uses tokens
    print("\n[1] First analysis (uncertain case 0.55 confidence) - will hit LLM")
    baseline = reasoner.deterministic.analyze(context)
    baseline.confidence_score = 0.55
    result1, meta1 = reasoner.analyze(context)
    
    print(f"    ✓ LLM Used: {meta1['llm_used']}")
    print(f"    ✓ Tokens Used: {meta1['tokens_used']}")
    print(f"    ✓ Budget Remaining: {meta1['budget_remaining']}")
    print(f"    ✓ Cache Hit: {meta1['cache_hit']}")
    
    # Second call - hits cache, zero tokens
    print("\n[2] Second analysis (same context) - will hit cache")
    result2, meta2 = reasoner.analyze(context)
    
    print(f"    ✓ LLM Used: {meta2['llm_used']}")
    print(f"    ✓ Tokens Used: {meta2['tokens_used']} (cached = no cost)")
    print(f"    ✓ Budget Remaining: {meta2['budget_remaining']}")
    print(f"    ✓ Cache Hit: {meta2['cache_hit']} ← YES!")
    print(f"\n    ✓ Results identical: {result1.narrative_explanation == result2.narrative_explanation}")


def demo_ja3_fingerprinting():
    """Demo: Expanded JA3 database."""
    print("\n" + "=" * 70)
    print("DEMO 2: Expanded JA3 Fingerprint Database")
    print("=" * 70)
    
    analyzer = NetworkVisibilityAnalyzer()
    
    print(f"\n✓ JA3 database has {len(analyzer.suspicious_ja3)} known-bad signatures:")
    for ja3_hash, description in list(analyzer.suspicious_ja3.items())[:5]:
        print(f"  - {ja3_hash[:16]}... → {description}")
    
    # Create event with known-bad JA3
    event = UnifiedSecurityEvent(
        event_id="net-1",
        timestamp=datetime.now(timezone.utc),
        entity_name="host-1",
        entity_id="host-1",
        entity_type="host",
        source_system="zeek",
        action="network_flow",
        raw_data={
            "ja3": "e7d705a3286e19ea42f587b344ee6865",  # Cobalt Strike
            "dest_ip": "203.0.113.50",
        },
    )
    
    score, findings = analyzer.score(event)
    print(f"\n✓ Known-bad JA3 (Cobalt Strike) detected:")
    print(f"  - Anomaly Score: {score:.2f}")
    print(f"  - Findings: {len(findings)} indicator(s)")
    for finding in findings:
        print(f"    - [{finding.rule_id}] {finding.description} (confidence: {finding.score})")


def demo_incident_queries_and_reputation():
    """Demo: Query methods + Entity reputation scoring."""
    print("\n" + "=" * 70)
    print("DEMO 3: Query Methods + Entity Reputation Scoring")
    print("=" * 70)
    
    # Create temp database
    temp_dir = tempfile.mkdtemp()
    db_path = Path(temp_dir) / "demo.sqlite3"
    store = IncidentStore(str(db_path))
    
    now = datetime.now(timezone.utc)
    
    # Add sample incidents
    print("\n✓ Adding sample incidents...")
    for i in range(7):
        record = DecisionRecord(
            triggering_events=[
                UnifiedSecurityEvent(
                    event_id=f"evt-{i}",
                    timestamp=now - timedelta(days=7 - i),
                    entity_name=f"host-{i % 2}",
                    entity_id=f"host-{i % 2}",
                    entity_type="host",
                    source_system="sysmon",
                    action="process",
                    raw_data={},
                )
            ],
            anomaly_scores=[0.5 + i * 0.05],
            classified_techniques=[
                {
                    "tactic": "Execution" if i % 2 == 0 else "Discovery",
                    "technique_id": f"T{1000 + i}",
                    "technique_name": f"Technique {i}",
                    "confidence": 0.6 + i * 0.05,
                }
            ],
            narrative=f"Sample incident {i}",
            predicted_next=[],
            recommended_actions=[],
            action_taken="alert",
            confidence_score=0.6 + i * 0.05,
        )
        store.save_decision(record)
    
    print("  ✓ 7 incidents stored")
    
    # Query by entity
    print("\n✓ Query by Entity (host-0):")
    host0_incidents = store.get_incidents_by_entity("host-0")
    print(f"  - Found {len(host0_incidents)} incidents")
    
    # Query by stage
    print("\n✓ Query by Stage (Execution):")
    exec_incidents = store.get_incidents_by_stage("Execution")
    print(f"  - Found {len(exec_incidents)} incidents with Execution tactic")
    
    # Query by confidence
    print("\n✓ Query by Confidence (>= 0.75):")
    high_conf = store.get_incidents_by_confidence(0.75)
    print(f"  - Found {len(high_conf)} high-confidence incidents")
    
    # Get entity statistics
    print("\n✓ Entity Statistics (host-0):")
    stats = store.get_entity_statistics("host-0")
    print(f"  - Total Incidents: {stats['total_incidents']}")
    print(f"  - Avg Confidence: {stats['avg_confidence']:.2f}")
    print(f"  - Max Confidence: {stats['max_confidence']:.2f}")
    print(f"  - Pending Review: {stats['pending_review']}")
    
    # Compute reputation
    print("\n✓ Entity Reputation Score (host-0):")
    rep = store.compute_entity_reputation("host-0", days_lookback=30)
    print(f"  - Reputation Score: {rep['reputation_score']:.3f}")
    print(f"  - Risk Level: {rep['risk_level'].upper()}")
    print(f"  - Factors:")
    for factor, score in rep["factors"].items():
        print(f"    - {factor}: {score:.3f}")


def demo_drift_detection():
    """Demo: Behavioral drift detection."""
    print("\n" + "=" * 70)
    print("DEMO 4: Behavioral Drift Detection (Long-term Analysis)")
    print("=" * 70)
    
    # Create temp database with drift data
    temp_dir = tempfile.mkdtemp()
    db_path = Path(temp_dir) / "drift_demo.sqlite3"
    store = IncidentStore(str(db_path))
    
    now = datetime.now(timezone.utc)
    
    # Populate with drift pattern: Low activity → High activity
    print("\n✓ Creating behavioral drift scenario...")
    print("  - Week 1-3: Low activity, Execution techniques")
    print("  - Week 4 (recent): High activity spike, Exfiltration techniques")
    
    # Week 1-3: Low activity
    for week in range(3, 0, -1):
        for day in range(7):
            record = DecisionRecord(
                triggering_events=[
                    UnifiedSecurityEvent(
                        event_id=f"drift-w{4-week}-d{day}",
                        timestamp=now - timedelta(days=week * 7 + day),
                        entity_name="drifting-host",
                        entity_id="drifting-host",
                        entity_type="host",
                        source_system="sysmon",
                        action="behavior",
                        raw_data={},
                    )
                ],
                anomaly_scores=[0.5],
                classified_techniques=[
                    {
                        "tactic": "Execution",
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "confidence": 0.6,
                    }
                ],
                narrative="Early week",
                predicted_next=[],
                recommended_actions=[],
                action_taken="monitor",
                confidence_score=0.5,
            )
            store.save_decision(record)
    
    # Week 4: High activity, different techniques
    for day in range(7):
        record = DecisionRecord(
            triggering_events=[
                UnifiedSecurityEvent(
                    event_id=f"drift-w4-d{day}",
                    timestamp=now - timedelta(days=day),
                    entity_name="drifting-host",
                    entity_id="drifting-host",
                    entity_type="host",
                    source_system="sysmon",
                    action="exfil",
                    raw_data={},
                )
            ],
            anomaly_scores=[0.85],
            classified_techniques=[
                {
                    "tactic": "Exfiltration",
                    "technique_id": "T1041",
                    "technique_name": "Exfiltration Over C2 Channel",
                    "confidence": 0.85,
                }
            ],
            narrative="Recent spike",
            predicted_next=[],
            recommended_actions=[],
            action_taken="escalate",
            confidence_score=0.85,
        )
        store.save_decision(record)
    
    # Analyze drift
    analyzer = BehavioralDriftAnalyzer(store)
    drift = analyzer.analyze_drift(
        "drifting-host",
        window_size_days=7,
        num_windows=4,
    )
    
    print(f"\n✓ Drift Analysis Results:")
    print(f"  - Frequency Drift: {drift['frequency_drift']:.3f} (high variance in incidents)")
    print(f"  - Confidence Drift: {drift['confidence_drift']:.3f} (avg confidence changed)")
    print(f"  - Technique Drift: {drift['technique_drift']:.3f} (different techniques used)")
    print(f"  - Overall Drift Score: {drift['overall_drift_score']:.3f}")
    
    print(f"\n✓ Anomalies Detected: {len(drift['anomalies'])}")
    for anomaly in drift["anomalies"]:
        print(f"  - [{anomaly['type']}] {anomaly.get('severity', 'info').upper()}")
        if "new_techniques" in anomaly:
            print(f"    New techniques: {', '.join(anomaly['new_techniques'])}")


def main():
    """Run all demos."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  SENTINEL NEW FEATURES IMPLEMENTATION DEMO".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")
    
    demo_token_budgeting_and_caching()
    demo_ja3_fingerprinting()
    demo_incident_queries_and_reputation()
    demo_drift_detection()
    
    print("\n" + "=" * 70)
    print("✓ ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
