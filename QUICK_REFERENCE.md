# Quick Reference: Using the 7 New Features

## 1️⃣ Token Budgeting + Response Caching

**What:** Control LLM costs. First call uses tokens; identical contexts cached.

```python
from sentinel.llm import SafetyEnvelopeReasoner

reasoner = SafetyEnvelopeReasoner(
    max_tokens_per_session=10000,  # ← Set budget
    enable_response_cache=True      # ← Enable caching
)

result, metadata = reasoner.analyze(context)

# Check spending
print(f"Tokens: {metadata['tokens_used']}")
print(f"Budget left: {metadata['budget_remaining']}")
print(f"Cached: {metadata['cache_hit']}")
```

**When to use:** Always! Protects against runaway costs.

---

## 2️⃣ Claude API Support

**What:** Use Claude instead of (or alongside) OpenAI.

```python
import os
os.environ["ANTHROPIC_API_KEY"] = "sk-ant-..."     # Set key

from sentinel.llm import AnthropicResponsesProvider, SafetyEnvelopeReasoner

provider = AnthropicResponsesProvider.from_env()    # Load from env
reasoner = SafetyEnvelopeReasoner(provider=provider)

result, metadata = reasoner.analyze(context)
```

**When to use:** When you prefer Claude's reasoning or already have Anthropic credits.

---

## 3️⃣ Expanded JA3 Fingerprinting

**What:** Detects 7 known-bad TLS fingerprints (was 1).

```python
from sentinel.network import NetworkVisibilityAnalyzer

analyzer = NetworkVisibilityAnalyzer()

# Verify database is expanded
print(f"Signatures: {len(analyzer.suspicious_ja3)}")  # 7

# Score network event
score, findings = analyzer.score(network_event)

for finding in findings:
    print(f"  [{finding.rule_id}] {finding.description} ({finding.score})")
```

**Detects:** Cobalt Strike, Darknet C2, Emotet, Mirai, Mimikatz, APT28

**When to use:** Automatically scored for all network events.

---

## 4️⃣ Incident Database Queries

**What:** Find incidents by entity, stage, confidence, or similarity.

```python
from sentinel.storage import IncidentStore

store = IncidentStore()

# All incidents for an entity
incidents = store.get_incidents_by_entity("host-123")

# By attack stage (tactic)
execution_incidents = store.get_incidents_by_stage("Execution")

# High confidence incidents
high_conf = store.get_incidents_by_confidence(min_confidence=0.75)

# Similar incidents (by technique/entity overlap)
similar = store.find_similar_incidents(decision_id="abc-123", limit=5)

# Entity leaderboard
top_entities = store.get_top_entities(limit=10)
```

**When to use:** Searching historical incidents, building reports.

---

## 5️⃣ Entity Statistics

**What:** Get aggregate stats for an entity.

```python
from sentinel.storage import IncidentStore

store = IncidentStore()

stats = store.get_entity_statistics("host-123")

print(f"Total incidents: {stats['total_incidents']}")
print(f"Avg confidence: {stats['avg_confidence']:.2f}")
print(f"Max confidence: {stats['max_confidence']:.2f}")
print(f"Reviewed: {stats['reviewed_count']}")
print(f"Pending review: {stats['pending_review']}")
```

**Output:** Incident count, confidence stats, review status

**When to use:** Analyst dashboards, entity profiles.

---

## 6️⃣ Entity Reputation Scoring

**What:** Compute entity risk (0-1 scale) from historical behavior.

```python
from sentinel.storage import IncidentStore

store = IncidentStore()

# Single entity
rep = store.compute_entity_reputation("host-123", days_lookback=30)

print(f"Score: {rep['reputation_score']:.3f}")     # 0-1
print(f"Risk: {rep['risk_level']}")                 # clean, low, medium, high
print(f"Incidents: {rep['incidents_in_period']}")

# See factors
for factor, value in rep['factors'].items():
    print(f"  {factor}: {value:.3f}")

# Top riskiest entities
leaderboard = store.get_entity_reputation_leaderboard(limit=10, days_lookback=30)
for entity in leaderboard:
    print(f"  {entity['entity_key']}: {entity['risk_level']} ({entity['reputation_score']:.3f})")
```

**Factors:** Frequency, confidence, recency, false-positive rate

**When to use:** Prioritizing investigation, threat hunting.

---

## 7️⃣ Behavioral Drift Detection

**What:** Detect changes in entity behavior over time windows.

```python
from sentinel.drift import BehavioralDriftAnalyzer
from sentinel.storage import IncidentStore

store = IncidentStore()
analyzer = BehavioralDriftAnalyzer(store)

# Analyze one entity
drift = analyzer.analyze_drift(
    entity_key="host-123",
    window_size_days=7,      # Weekly windows
    num_windows=4            # 4 weeks back
)

print(f"Overall drift: {drift['overall_drift_score']:.3f}")
print(f"Frequency drift: {drift['frequency_drift']:.3f}")   # Incident rate variance
print(f"Confidence drift: {drift['confidence_drift']:.3f}") # Confidence variance
print(f"Technique drift: {drift['technique_drift']:.3f}")   # Technique overlap

# See anomalies
for anomaly in drift['anomalies']:
    print(f"  [{anomaly['type']}] {anomaly['severity'].upper()}")
    if 'new_techniques' in anomaly:
        print(f"    New: {anomaly['new_techniques']}")

# Find all drifting entities
drifting = analyzer.detect_all_drifting_entities(
    drift_threshold=0.6,     # Flag if drift > 0.6
    window_size_days=7,
    num_windows=4
)

print(f"Drifting entities: {len(drifting)}")
```

**Detects:**
- Frequency spikes (incident rate change)
- Confidence escalation (avg confidence change)
- New techniques (different TTPs)

**When to use:** Threat hunting, behavioral profiling, campaign detection.

---

## 📋 Complete Example: Full Pipeline

```python
from sentinel.llm import AnthropicResponsesProvider, SafetyEnvelopeReasoner
from sentinel.storage import IncidentStore
from sentinel.drift import BehavioralDriftAnalyzer

# 1. Set up LLM with budget & cache
provider = AnthropicResponsesProvider.from_env()
reasoner = SafetyEnvelopeReasoner(
    provider=provider,
    max_tokens_per_session=50000,
    enable_response_cache=True
)

# 2. Analyze events
result, metadata = reasoner.analyze(event_context)
print(f"Analysis: {result.narrative_explanation}")
print(f"Cost: {metadata['tokens_used']} tokens")

# 3. Store decision
store = IncidentStore()
store.save_decision(decision_record)

# 4. Query for similar incidents
similar = store.find_similar_incidents(decision_record.decision_id)
print(f"Found {len(similar)} similar incidents")

# 5. Check entity reputation
rep = store.compute_entity_reputation(entity_id)
print(f"Entity risk level: {rep['risk_level']}")

# 6. Detect behavioral drift
analyzer = BehavioralDriftAnalyzer(store)
drift = analyzer.analyze_drift(entity_id, window_size_days=7, num_windows=4)
if drift['overall_drift_score'] > 0.6:
    print(f"⚠️  Behavioral shift detected!")
    for anomaly in drift['anomalies']:
        print(f"  - {anomaly['type']}")
```

---

## 🔑 Key Takeaways

| Feature | Key Benefit | Default |
|---------|------------|---------|
| Token Budgeting | **Cost control** | No limit |
| Caching | **80% cost savings** | Enabled |
| Claude | **Model flexibility** | Optional |
| JA3 | **TLS threat detection** | 7 signatures |
| Queries | **Historical search** | 6 methods |
| Reputation | **Risk prioritization** | Per-entity |
| Drift | **Pattern detection** | Weekly windows |

---

## 🚀 Getting Started

1. **Run tests:** `python -m unittest tests.test_new_features -v`
2. **Run demo:** `python demo_new_features.py`
3. **Use in code:** Import from `sentinel.llm`, `sentinel.storage`, `sentinel.drift`

---

## 📖 Documentation

- `COMPLETE_SUMMARY.md` — Full implementation summary
- `IMPLEMENTATION_STATUS.md` — Detailed feature status
- `IMPLEMENTATION_& _TEST_RESULTS.md` — Test results and usage
- `tests/test_new_features.py` — 27 test examples
- `demo_new_features.py` — Live working demonstrations
