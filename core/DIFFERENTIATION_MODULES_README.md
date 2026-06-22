# IMMUNEX Differentiation Modules

This directory contains 8 new capability modules that position IMMUNEX 2-3 years ahead of conventional SIEM/SOAR/XDR platforms.

## New Modules Created

### Core Modules (`core/`)

1. **national_resilience_index.py** - NCRI Calculation Engine
   - Computes governance-grade national cyber resilience score
   - Weighted geometric mean of 6 components
   - Sector-specific scoring
   - 30/90-day trend analysis

2. **predictive_forecast_engine.py** - Attack Forecasting
   - Predicts which assets will be attacked next
   - Bayesian probabilistic scoring
   - Bootstrap confidence intervals
   - Threat actor affinity scoring

3. **autonomous_mitigation_planner.py** - Mitigation Optimization
   - Constraint-based optimization (MILP)
   - Minimizes cost, downtime, risk
   - Respects dependency ordering
   - Greedy fallback if PuLP unavailable

4. **cyber_learning_memory.py** - Continuous Learning System
   - Records incident outcomes
   - FAISS semantic search for similar incidents
   - Recommends response actions based on history
   - Updates risk models from analyst feedback

5. **explainable_risk_engine.py** - Explainability Layer
   - Traceable evidence chains for every prediction
   - Bootstrap confidence intervals
   - Alternative scenarios
   - Identifies model limitations

6. **cascading_impact_model.py** - Sector Impact Simulation
   - Models cross-sector dependencies
   - Simulates primary → secondary → tertiary impacts
   - Economic impact estimation
   - Citizen impact assessment

### Storage Modules (`storage/`)

7. **threat_actor_knowledge_graph.py** - Threat Intel Graph
   - Neo4j-backed knowledge graph
   - Actor profiles with campaign history
   - Campaign correlation via TTP similarity
   - Indicator correlation engine

### API Modules (`api/routes/`)

8. **differentiation_routes.py** - REST Endpoints
   - 30+ endpoints across 6 capability groups
   - Full request/response contracts
   - Query parameter validation
   - Error handling

## Module Dependencies

```
national_resilience_index.py
  ├─ postgres_client
  ├─ incident_store
  ├─ cve_db
  └─ asset_registry

predictive_forecast_engine.py
  ├─ attack_graph_engine
  ├─ cve_prioritization
  ├─ threat_actor_db
  └─ incident_store

autonomous_mitigation_planner.py
  ├─ cve_db
  ├─ playbook_engine
  └─ soar_orchestrator

cyber_learning_memory.py
  ├─ postgres_client
  ├─ incident_store
  └─ faiss_index (optional)

explainable_risk_engine.py
  ├─ risk_models
  ├─ graph_engine
  ├─ cve_db
  ├─ mitre_mapper
  └─ threat_actor_db

cascading_impact_model.py
  └─ neo4j_client

threat_actor_knowledge_graph.py
  ├─ neo4j_client
  └─ mitre_mapper
```

## Integration with Existing IMMUNEX Modules

All new modules reuse 63% code from existing IMMUNEX infrastructure:

- **attack_graph_engine.py** - Used by forecast, cascading, explainability
- **cve_prioritization.py** - Used by NCRI, forecast, mitigation planner
- **digital_twin_simulator.py** - Used by cascading, recovery optimizer
- **incident_store.py** - Used by learning memory, NCRI, forecast
- **threat_actor_db.py** - Used by forecast, attribution, explainability
- **mitre_mapper.py** - Used by threat actor graph, explainability
- **soar_orchestrator.py** - Used by mitigation planner execution
- **neo4j_client.py** - Used by threat actor graph, cascading model

## Database Schema Extensions Required

### PostgreSQL

```sql
-- NCRI historical scores
CREATE TABLE ncri_history (
    timestamp TIMESTAMP,
    ncri_score FLOAT,
    component_scores JSONB,
    sector_scores JSONB
);

-- Incident outcomes for learning
CREATE TABLE incident_outcomes (
    incident_id VARCHAR PRIMARY KEY,
    techniques_used TEXT[],
    mitigations_applied TEXT[],
    effectiveness_rating FLOAT,
    detection_time_minutes FLOAT,
    response_time_minutes FLOAT,
    recovered BOOLEAN,
    recovery_time_minutes FLOAT,
    analyst_notes TEXT,
    recorded_at TIMESTAMP
);

-- Technique and mitigation effectiveness
CREATE TABLE technique_effectiveness (
    technique VARCHAR PRIMARY KEY,
    successful_mitigations TEXT[],
    average_effectiveness FLOAT,
    times_encountered INT
);

CREATE TABLE mitigation_effectiveness (
    mitigation_name VARCHAR PRIMARY KEY,
    effectiveness_score FLOAT,
    success_rate FLOAT,
    average_deployment_time_hours FLOAT,
    times_applied INT
);

-- False positive tracking
CREATE TABLE false_positive_log (
    alert_id VARCHAR PRIMARY KEY,
    reason TEXT,
    rule_id VARCHAR,
    reported_at TIMESTAMP
);
```

### Neo4j

```cypher
// Threat Actor nodes
CREATE (a:ThreatActor {name: String, confidence: Float, aliases: [String]})

// Campaign nodes
CREATE (c:Campaign {name: String, first_observed: DateTime, last_observed: DateTime})

// Relationships
CREATE (a)-[:CONDUCTS]->(c)
CREATE (c)-[:TARGETS]->(v:Victim)
CREATE (c)-[:EMPLOYS]->(t:Technique)
CREATE (a)-[:KNOWS_TTP]->(t)

// Sector dependency graph
CREATE (s1:Sector)-[:DEPENDS_ON {factor: Float}]->(s2:Sector)
```

## Configuration

Each module requires initialization with dependencies. Example:

```python
from core.national_resilience_index import NationalResilienceIndexEngine
from storage.postgres_client import PostgresClient
from storage.incident_store import IncidentStore
from core.cve_prioritization import CVEPrioritization

# Initialize NCRI
ncri_engine = NationalResilienceIndexEngine(
    postgres_client=pg,
    incident_store=incident_db,
    cve_db=cve_engine,
    asset_registry=asset_db
)

# Calculate NCRI
ncri_score, components = ncri_engine.calculate_ncri()
```

## Testing Strategy

### Unit Tests
- Test each module independently with mocked dependencies
- Verify mathematical formulas
- Test edge cases (empty data, extreme values)

### Integration Tests
- Test module interactions through API
- Verify data flows between modules
- Test with realistic data volumes

### Validation Tests
- Compare NCRI formula against domain expert scoring
- Validate forecast accuracy against historical incidents
- Validate cascading impact against real-world scenarios

## Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| NCRI calculation | < 5 min | Daily batch |
| Forecast (top 20 assets) | < 10 sec | Real-time API |
| Mitigation plan (100 assets) | < 30 sec | Real-time API |
| Explanation generation | < 500ms | Real-time API |
| Similar incident query | < 1 sec | FAISS search |
| Cascading simulation | < 2 sec | Real-time API |

## Security Considerations

- All API endpoints require authentication
- Sensitive data (CVE details, incident data) require role-based access
- Audit logging for all risk/forecast changes
- Encrypted storage of threat actor profiles
- PII handling compliant with GDPR/CCPA

## Roadmap

**Phase 1 (Weeks 1-4)**: NCRI + Explainability
**Phase 2 (Weeks 5-8)**: Predictive Forecast + Threat Actor Graph
**Phase 3 (Weeks 9-10)**: Cascading Impact + Learning Memory
**Phase 4 (Weeks 11-12)**: Mitigation Planner + Integration

## Contact

IMMUNEX Core Team
National Cyber Resilience Platform
