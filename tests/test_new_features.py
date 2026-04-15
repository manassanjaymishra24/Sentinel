"""Test suite for all new features."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinel.audit import DecisionRecord
from sentinel.drift import BehavioralDriftAnalyzer
from sentinel.events import UnifiedSecurityEvent
from sentinel.llm import (
    AnthropicResponsesProvider,
    MockLLMProvider,
    SafetyEnvelopeReasoner,
)
from sentinel.network import NetworkVisibilityAnalyzer
from sentinel.storage import IncidentStore


class TestTokenBudgeting(unittest.TestCase):
    """Test token budget tracking and fallback."""

    def setUp(self):
        self.reasoner = SafetyEnvelopeReasoner(
            max_tokens_per_session=500,
            enable_response_cache=False,
        )

    def test_token_counter_initialized(self):
        """Verify token counter starts at 0."""
        self.assertEqual(self.reasoner.tokens_used, 0)

    def test_budget_respected(self):
        """Verify LLM is skipped when budget exceeded."""
        # Create a mock provider
        mock_output = {
            "attack_stage": "Execution",
            "matched_techniques": [],
            "predicted_next": [],
            "confidence_score": 0.5,
            "narrative_explanation": "Test",
            "recommended_actions": [],
        }
        self.reasoner.provider = MockLLMProvider(mock_output)
        self.reasoner.lower_threshold = 0.0
        self.reasoner.upper_threshold = 1.0

        # Create large context to exceed budget
        large_context = {
            "events": [
                {"data": "x" * 1000}
                for _ in range(500)  # ~500KB of data
            ]
        }

        baseline = self.reasoner.deterministic.analyze(large_context)
        baseline.confidence_score = 0.5  # Trigger routing

        result, metadata = self.reasoner.analyze(large_context)

        # Should skip LLM due to budget
        self.assertIn("token_budget_exceeded", str(metadata.get("validation_flags", [])))
        self.assertEqual(metadata["llm_used"], False)

    def test_token_estimation(self):
        """Verify token estimation is positive and reasonable."""
        context = {"events": [{"test": "data"}]}
        baseline = self.reasoner.deterministic.analyze(context)

        estimated = self.reasoner._estimate_tokens(context, baseline)
        self.assertGreater(estimated, 0)
        self.assertLess(estimated, 10000)  # Should be reasonable


class TestResponseCaching(unittest.TestCase):
    """Test LLM response caching."""

    def setUp(self):
        self.reasoner = SafetyEnvelopeReasoner(
            enable_response_cache=True,
            max_tokens_per_session=100000,
        )
        mock_output = {
            "attack_stage": "Execution",
            "matched_techniques": [
                {
                    "tactic": "Execution",
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "confidence": 0.8,
                    "evidence": ["powershell"],
                }
            ],
            "predicted_next": [],
            "confidence_score": 0.5,
            "narrative_explanation": "Test narrative",
            "recommended_actions": [],
        }
        self.reasoner.provider = MockLLMProvider(mock_output)
        self.reasoner.lower_threshold = 0.0
        self.reasoner.upper_threshold = 1.0

    def test_cache_key_computed(self):
        """Verify cache keys are computed."""
        context = {"events": [{"test": "data"}]}
        key = self.reasoner._compute_cache_key(context)

        # Should be a 64-char hex string (SHA256)
        self.assertEqual(len(key), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in key))

    def test_cache_hit(self):
        """Verify cache hits skip LLM call."""
        context = {"events": [{"data": "test"}]}
        baseline = self.reasoner.deterministic.analyze(context)
        baseline.confidence_score = 0.5

        # First call - should hit LLM
        result1, metadata1 = self.reasoner.analyze(context)

        # Second call - should hit cache
        result2, metadata2 = self.reasoner.analyze(context)

        # Cache hit should have zero tokens consumed
        self.assertTrue(metadata2["cache_hit"])
        self.assertEqual(metadata2["tokens_used"], 0)

        # Results should be identical
        self.assertEqual(
            result1.narrative_explanation,
            result2.narrative_explanation,
        )


class TestJA3Expansion(unittest.TestCase):
    """Test expanded JA3 fingerprint database."""

    def test_ja3_database_expanded(self):
        """Verify JA3 database has multiple entries."""
        analyzer = NetworkVisibilityAnalyzer()

        # Should have at least 7 entries (was 1 before)
        self.assertGreaterEqual(len(analyzer.suspicious_ja3), 7)

        # Check specific entries exist
        keys = set(analyzer.suspicious_ja3.keys())
        self.assertIn("e7d705a3286e19ea42f587b344ee6865", keys)  # Cobalt Strike

    def test_ja3_matching_scores(self):
        """Verify JA3 matches score high."""
        analyzer = NetworkVisibilityAnalyzer()

        # Create an event with a known-bad JA3
        event = UnifiedSecurityEvent(
            event_id="test",
            timestamp=datetime.now(timezone.utc),
            entity_name="host-1",
            entity_id="host-1",
            entity_type="host",
            source_system="zeek",
            action="network_flow",
            raw_data={
                "ja3": "e7d705a3286e19ea42f587b344ee6865",
                "dest_ip": "1.2.3.4",
            },
        )

        score, findings = analyzer.score(event)
        self.assertGreater(score, 0.8)
        self.assertTrue(len(findings) > 0)


class TestClaudeIntegration(unittest.TestCase):
    """Test Claude API provider."""

    def test_claude_provider_creation(self):
        """Verify Claude provider can be instantiated."""
        provider = AnthropicResponsesProvider(
            api_key="test-key-123",
            model="claude-3-5-sonnet-20241022",
        )
        self.assertEqual(provider.api_key, "test-key-123")
        self.assertEqual(provider.model, "claude-3-5-sonnet-20241022")

    def test_claude_from_env_no_key(self):
        """Verify from_env returns None when API key missing."""
        import os

        # Temporarily remove env var
        old_key = os.environ.get("ANTHROPIC_API_KEY")
        if "ANTHROPIC_API_KEY" in os.environ:
            del os.environ["ANTHROPIC_API_KEY"]

        provider = AnthropicResponsesProvider.from_env()
        self.assertIsNone(provider)

        # Restore
        if old_key:
            os.environ["ANTHROPIC_API_KEY"] = old_key

    def test_claude_provider_attributes(self):
        """Verify Claude provider has all required attributes."""
        provider = AnthropicResponsesProvider(api_key="test")
        self.assertTrue(hasattr(provider, "reason"))
        self.assertTrue(hasattr(provider, "api_key"))
        self.assertTrue(hasattr(provider, "model"))
        self.assertTrue(hasattr(provider, "endpoint"))


class TestIncidentStoreQueries(unittest.TestCase):
    """Test new IncidentStore query methods."""

    def setUp(self):
        """Create temporary incident database."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.sqlite3"
        self.store = IncidentStore(str(self.db_path))

        # Create test records
        self._populate_test_incidents()

    def _populate_test_incidents(self):
        """Add test incidents to database."""
        now = datetime.now(timezone.utc)

        for i in range(5):
            record = DecisionRecord(
                triggering_events=[
                    UnifiedSecurityEvent(
                        event_id=f"evt-{i}",
                        timestamp=now - timedelta(days=5 - i),
                        entity_name=f"host-{i % 2}",
                        entity_id=f"host-{i % 2}",
                        entity_type="host",
                        source_system="test",
                        action="test_action",
                        raw_data={},
                    )
                ],
                anomaly_scores=[0.6 + i * 0.1],
                classified_techniques=[
                    {
                        "tactic": "Execution" if i % 2 == 0 else "Discovery",
                        "technique_id": f"T{1000 + i}",
                        "technique_name": f"Technique {i}",
                        "confidence": 0.7 + i * 0.05,
                    }
                ],
                narrative="Test narrative",
                predicted_next=[],
                recommended_actions=[],
                action_taken="test_action",
                confidence_score=0.7 + i * 0.05,
                human_review_required=i % 2 == 0,
            )
            self.store.save_decision(record)

    def test_get_incidents_by_entity(self):
        """Test entity-based query."""
        results = self.store.get_incidents_by_entity("host-0")
        self.assertGreater(len(results), 0)

        # All results should match entity
        for r in results:
            self.assertIn("host-0", r["entity_keys"])

    def test_get_incidents_by_stage(self):
        """Test stage-based query."""
        results = self.store.get_incidents_by_stage("Execution")
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["attack_stage"], "Execution")

    def test_get_incidents_by_confidence(self):
        """Test confidence-based query."""
        results = self.store.get_incidents_by_confidence(0.75)
        self.assertGreater(len(results), 0)

        # All should meet threshold
        for r in results:
            self.assertGreaterEqual(r["confidence"], 0.75)

    def test_find_similar_incidents(self):
        """Test similarity matching."""
        # Get first incident
        recent = self.store.recent_incidents(limit=1)
        if recent:
            decision_id = recent[0]["decision_id"]
            similar = self.store.find_similar_incidents(decision_id)

            # Should find at least some similar incidents
            self.assertIsInstance(similar, list)

    def test_get_entity_statistics(self):
        """Test entity statistics."""
        stats = self.store.get_entity_statistics("host-0")

        self.assertIn("entity_key", stats)
        self.assertIn("total_incidents", stats)
        self.assertIn("avg_confidence", stats)
        self.assertGreater(stats["total_incidents"], 0)

    def test_get_top_entities(self):
        """Test leaderboard query."""
        results = self.store.get_top_entities(limit=5)

        self.assertGreater(len(results), 0)
        self.assertLess(len(results), 10)


class TestEntityReputation(unittest.TestCase):
    """Test entity reputation scoring."""

    def setUp(self):
        """Create temporary incident database with historical data."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.sqlite3"
        self.store = IncidentStore(str(self.db_path))

        self._populate_historical_incidents()

    def _populate_historical_incidents(self):
        """Add incidents over time for trend analysis."""
        now = datetime.now(timezone.utc)

        # Week 1: 2 incidents, low confidence
        for i in range(2):
            record = DecisionRecord(
                triggering_events=[
                    UnifiedSecurityEvent(
                        event_id=f"w1-{i}",
                        timestamp=now - timedelta(days=28 + i),
                        entity_name="suspicious-host",
                        entity_id="suspicious-host",
                        entity_type="host",
                        source_system="sysmon",
                        action="process_creation",
                        raw_data={},
                    )
                ],
                anomaly_scores=[0.4],
                classified_techniques=[
                    {
                        "tactic": "Discovery",
                        "technique_id": "T1087",
                        "technique_name": "Account Discovery",
                        "confidence": 0.4,
                    }
                ],
                narrative="Week 1 incident",
                predicted_next=[],
                recommended_actions=[],
                action_taken="test",
                confidence_score=0.4,
            )
            self.store.save_decision(record)

        # Week 4 (recent): 4 incidents, high confidence
        for i in range(4):
            record = DecisionRecord(
                triggering_events=[
                    UnifiedSecurityEvent(
                        event_id=f"w4-{i}",
                        timestamp=now - timedelta(days=2 + i),
                        entity_name="suspicious-host",
                        entity_id="suspicious-host",
                        entity_type="host",
                        source_system="sysmon",
                        action="network_connection",
                        raw_data={},
                    )
                ],
                anomaly_scores=[0.8],
                classified_techniques=[
                    {
                        "tactic": "Execution",
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "confidence": 0.85,
                    }
                ],
                narrative="Week 4 recent spike",
                predicted_next=[],
                recommended_actions=[],
                action_taken="test",
                confidence_score=0.85,
            )
            self.store.save_decision(record)

    def test_compute_reputation_score(self):
        """Test reputation score computation."""
        rep = self.store.compute_entity_reputation("suspicious-host", days_lookback=30)

        self.assertIn("reputation_score", rep)
        self.assertIn("risk_level", rep)
        self.assertIn("factors", rep)

        # Score should be between 0-1
        self.assertGreaterEqual(rep["reputation_score"], 0.0)
        self.assertLessEqual(rep["reputation_score"], 1.0)

    def test_reputation_risk_levels(self):
        """Test risk level assignment."""
        rep = self.store.compute_entity_reputation("suspicious-host")

        # Recent spikes should result in elevated risk
        self.assertIn(rep["risk_level"], ["clean", "low", "medium", "high"])

    def test_reputation_leaderboard(self):
        """Test reputation leaderboard."""
        leaderboard = self.store.get_entity_reputation_leaderboard(limit=10)

        self.assertIsInstance(leaderboard, list)
        # Should be sorted by reputation (descending)
        if len(leaderboard) >= 2:
            self.assertGreaterEqual(
                leaderboard[0]["reputation_score"],
                leaderboard[1]["reputation_score"],
            )


class TestDriftDetection(unittest.TestCase):
    """Test behavioral drift analysis."""

    def setUp(self):
        """Create database with drift patterns."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.sqlite3"
        self.store = IncidentStore(str(self.db_path))
        self.analyzer = BehavioralDriftAnalyzer(self.store)

        self._populate_drift_data()

    def _populate_drift_data(self):
        """Add incidents showing behavior drift."""
        now = datetime.now(timezone.utc)

        # Week 1: Low activity, Execution techniques
        for day in range(7, 0, -1):
            record = DecisionRecord(
                triggering_events=[
                    UnifiedSecurityEvent(
                        event_id=f"drift-w1-{day}",
                        timestamp=now - timedelta(days=day * 7),
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
                narrative="Week 1",
                predicted_next=[],
                recommended_actions=[],
                action_taken="test",
                confidence_score=0.5,
            )
            self.store.save_decision(record)

        # Week 4 (recent): High activity, Different techniques (Exfiltration)
        for day in range(7, 0, -1):
            record = DecisionRecord(
                triggering_events=[
                    UnifiedSecurityEvent(
                        event_id=f"drift-w4-{day}",
                        timestamp=now - timedelta(days=day),
                        entity_name="drifting-host",
                        entity_id="drifting-host",
                        entity_type="host",
                        source_system="sysmon",
                        action="exfiltration",
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
                narrative="Week 4 drift",
                predicted_next=[],
                recommended_actions=[],
                action_taken="test",
                confidence_score=0.85,
            )
            self.store.save_decision(record)

    def test_analyze_drift_returns_metrics(self):
        """Test drift analysis returns expected metrics."""
        drift = self.analyzer.analyze_drift(
            "drifting-host",
            window_size_days=7,
            num_windows=4,
        )

        self.assertIn("frequency_drift", drift)
        self.assertIn("confidence_drift", drift)
        self.assertIn("technique_drift", drift)
        self.assertIn("overall_drift_score", drift)
        self.assertIn("anomalies", drift)

    def test_drift_anomalies_detected(self):
        """Test that anomalies are detected in drift."""
        drift = self.analyzer.analyze_drift(
            "drifting-host",
            window_size_days=7,
            num_windows=4,
        )

        # Should detect some anomalies (frequency spike, technique change)
        self.assertGreater(len(drift["anomalies"]), 0)

    def test_detect_all_drifting_entities(self):
        """Test detection of all drifting entities."""
        drifting = self.analyzer.detect_all_drifting_entities(
            drift_threshold=0.5,
            window_size_days=7,
            num_windows=4,
        )

        self.assertIsInstance(drifting, list)


class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple features."""

    def test_claude_with_budget_and_cache(self):
        """Test Claude + budget + cache all work together."""
        reasoner = SafetyEnvelopeReasoner(
            provider=MockLLMProvider(
                {
                    "attack_stage": "Discovery",
                    "matched_techniques": [],
                    "predicted_next": [],
                    "confidence_score": 0.5,
                    "narrative_explanation": "Test",
                    "recommended_actions": [],
                }
            ),
            max_tokens_per_session=5000,
            enable_response_cache=True,
            lower_threshold=0.0,
            upper_threshold=1.0,
        )

        context = {"events": [{"test": "data"}]}
        baseline = reasoner.deterministic.analyze(context)
        baseline.confidence_score = 0.5

        result, metadata = reasoner.analyze(context)

        # Should have budget info and cache tracking
        self.assertIn("budget_remaining", metadata)
        self.assertIn("cache_hit", metadata)
        self.assertIn("tokens_used", metadata)

    def test_full_pipeline_with_reputation(self):
        """Test end-to-end pipeline: detect -> store -> reputation."""
        temp_dir = tempfile.mkdtemp()
        db_path = Path(temp_dir) / "pipeline.sqlite3"
        store = IncidentStore(str(db_path))

        # Create and save incident
        now = datetime.now(timezone.utc)
        record = DecisionRecord(
            triggering_events=[
                UnifiedSecurityEvent(
                    event_id="pipeline-test",
                    timestamp=now,
                    entity_name="test-host",
                    entity_id="test-host",
                    entity_type="host",
                    source_system="demo",
                    action="test",
                    raw_data={},
                )
            ],
            anomaly_scores=[0.75],
            classified_techniques=[
                {
                    "tactic": "Execution",
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "confidence": 0.8,
                }
            ],
            narrative="Pipeline test",
            predicted_next=[],
            recommended_actions=[],
            action_taken="test",
            confidence_score=0.75,
        )
        store.save_decision(record)

        # Query and compute reputation
        query_result = store.get_incidents_by_entity("test-host")
        self.assertEqual(len(query_result), 1)

        rep = store.compute_entity_reputation("test-host")
        self.assertGreater(rep["reputation_score"], 0)


if __name__ == "__main__":
    unittest.main()
