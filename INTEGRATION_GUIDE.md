# IMMUNEX Module Integration Guide

Quick reference for integrating 8 differentiation modules into existing IMMUNEX codebase.

## 1. IMPORT NEW MODULES

Add to `main.py`:

```python
# New differentiation capabilities
from core.national_resilience_index import NationalResilienceIndexEngine
from core.predictive_forecast_engine import PredictiveAttackForecastEngine
from core.autonomous_mitigation_planner import AutonomousMitigationPlanner
from core.cyber_learning_memory import CyberLearningMemory
from core.explainable_risk_engine import ExplainableRiskEngine
from core.cascading_impact_model import CascadingFailureSimulator
from storage.threat_actor_knowledge_graph import ThreatActorKnowledgeGraph
```

## 2. INITIALIZE MODULES IN PIPELINE

Add to `main.py` initialization:

```python
# Initialize differentiation engines
ncri_engine = NationalResilienceIndexEngine(
    postgres_client=postgres,
    incident_store=incident_store,
    cve_db=cve_engine,
    asset_registry=asset_registry
)

forecast_engine = PredictiveAttackForecastEngine(
    attack_graph_engine=attack_graph,
    cve_prioritization=cve_engine,
    threat_actor_db=threat_actor_db,
    incident_store=incident_store
)

mitigation_planner = AutonomousMitigationPlanner(
    cve_db=cve_engine,
    playbook_engine=playbook_engine,
    soar_orchestrator=soar_orchestrator
)

learning_memory = CyberLearningMemory(
    postgres_client=postgres,
    incident_store=incident_store,
    faiss_index=faiss_index  # Optional
)

explainability_engine = ExplainableRiskEngine(
    risk_models=risk_models,
    graph_engine=attack_graph,
    cve_db=cve_engine,
    mitre_mapper=mitre_mapper,
    threat_actor_db=threat_actor_db
)

cascading_simulator = CascadingFailureSimulator(
    neo4j_client=neo4j
)

threat_actor_graph = ThreatActorKnowledgeGraph(
    neo4j_client=neo4j,
    mitre_mapper=mitre_mapper
)
```

## 3. ADD API ROUTES

Add to `api/api_server.py`:

```python
from api.routes.differentiation_routes import include_differentiation_routes

# Create app
app = FastAPI(title="IMMUNEX Differentiation API")

# Include all differentiation routes
include_differentiation_routes(app)

# Start server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

## 4. INTEGRATE INTO PIPELINE LAYERS

Add calls to differentiation engines in main pipeline:

### Layer 1 (Innate Immunity)
```python
# Existing attack detection
threats = detect_threats(events)
```

### Layer 2 (Adaptive Intelligence) - ADD HERE
```python
# NEW: Predict future attacks
forecasts = forecast_engine.forecast_next_attacks(horizon_days=30, top_k=20)

# NEW: Score threat actor likelihood
actor_scores = threat_actor_graph.attribute_incident_to_actor(
    techniques=detected_techniques,
    malware_hashes=detected_hashes
)

# NEW: Generate explanations
explanations = explainability_engine.explain_asset_risk(asset_ip)

# NEW: Calculate NCRI
ncri_score, components = ncri_engine.calculate_ncri()
```

### Layer 3 (Immune Response) - ADD HERE
```python
# Existing: Execute playbooks
playbook_result = execute_playbook(threat)

# NEW: Record outcome for learning
learning_memory.record_incident_outcome(
    incident_id=threat['id'],
    techniques_used=threat['techniques'],
    mitigations_applied=playbook_result['mitigations'],
    effectiveness_rating=playbook_result['effectiveness'],
    detection_time_minutes=threat['detection_time'],
    response_time_minutes=playbook_result['execution_time'],
    recovered=playbook_result['success'],
    recovery_time_minutes=playbook_result['recovery_time']
)

# NEW: Plan optimized mitigations
mitigation_plan = mitigation_planner.plan_mitigations(
    critical_assets=critical_assets,
    budget_dollars=budget,
    max_downtime_hours=max_downtime
)

# NEW: Simulate cascading impact
cascade_analysis = cascading_simulator.simulate_sector_compromise(
    compromised_sector=threat['sector'],
    attacker_capability='intermediate'
)
```

### Layer 4 (Adaptive Immunization) - ADD HERE
```python
# Existing: Update signatures and rules
update_signatures(threat)

# NEW: Update threat actor graph
threat_actor_graph.add_campaign(campaign_data)

# NEW: Provide feedback for learning
learning_memory.update_risk_model_from_feedback({
    'forecast_accuracy': was_accurate,
    'is_false_positive': is_fp
})
```

## 5. DATABASE SETUP

Run migrations (PostgreSQL):

```sql
-- NCRI historical tracking
CREATE TABLE IF NOT EXISTS ncri_history (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    ncri_score FLOAT NOT NULL,
    component_scores JSONB,
    sector_scores JSONB,
    INDEX (timestamp DESC)
);

-- Incident outcomes for learning
CREATE TABLE IF NOT EXISTS incident_outcomes (
    incident_id VARCHAR PRIMARY KEY,
    techniques_used TEXT[],
    mitigations_applied TEXT[],
    effectiveness_rating FLOAT,
    detection_time_minutes FLOAT,
    response_time_minutes FLOAT,
    recovered BOOLEAN,
    recovery_time_minutes FLOAT,
    analyst_notes TEXT,
    recorded_at TIMESTAMP DEFAULT NOW(),
    INDEX (techniques_used, recorded_at DESC)
);

-- Mitigation effectiveness tracking
CREATE TABLE IF NOT EXISTS mitigation_effectiveness (
    mitigation_name VARCHAR PRIMARY KEY,
    effectiveness_score FLOAT,
    success_rate FLOAT,
    avg_deployment_hours FLOAT,
    times_applied INT,
    last_updated TIMESTAMP DEFAULT NOW()
);

-- False positive log
CREATE TABLE IF NOT EXISTS false_positive_log (
    alert_id VARCHAR PRIMARY KEY,
    reason TEXT,
    rule_id VARCHAR,
    reported_at TIMESTAMP DEFAULT NOW()
);
```

Initialize Neo4j graph schema:

```cypher
CREATE CONSTRAINT unique_threat_actor ON (a:ThreatActor) ASSERT a.name IS UNIQUE;
CREATE CONSTRAINT unique_campaign ON (c:Campaign) ASSERT c.name IS UNIQUE;
CREATE CONSTRAINT unique_technique ON (t:Technique) ASSERT t.id IS UNIQUE;
CREATE INDEX idx_actor_confidence ON :ThreatActor(confidence);
CREATE INDEX idx_campaign_observed ON :Campaign(last_observed);
```

## 6. DEPENDENCY INSTALLATION

```bash
pip install pulp faiss-cpu neo4j numpy scipy scikit-learn
```

## 7. UNIT TEST STRUCTURE

Create `tests/test_differentiation_modules.py`:

```python
import pytest
from core.national_resilience_index import NationalResilienceIndexEngine
from core.predictive_forecast_engine import PredictiveAttackForecastEngine
# ... etc

class TestNCRI:
    def test_ncri_calculation(self, mock_postgres, mock_incident_store):
        ncri_engine = NationalResilienceIndexEngine(
            postgres_client=mock_postgres,
            incident_store=mock_incident_store,
            cve_db=None,
            asset_registry=None
        )
        score, components = ncri_engine.calculate_ncri()
        assert 0.0 <= score <= 1.0
        assert len(components) == 6

class TestPredictiveForecast:
    def test_forecast_attack(self, mock_graph):
        forecast_engine = PredictiveAttackForecastEngine(
            attack_graph_engine=mock_graph,
            cve_prioritization=None,
            threat_actor_db=None,
            incident_store=None
        )
        forecasts = forecast_engine.forecast_next_attacks(horizon_days=30)
        assert len(forecasts) > 0
        for f in forecasts:
            assert 0.0 <= f.attack_probability <= 1.0
            assert len(f.confidence_interval) == 2
```

## 8. MONITORING & LOGGING

Add to `telemetry/telemetry_profiler.py`:

```python
import logging

logger = logging.getLogger(__name__)

def log_ncri_calculation(ncri_score, components):
    logger.info(f"NCRI calculated: {ncri_score:.4f}")
    for name, component in components.items():
        logger.debug(f"  {name}: {component.raw_score:.4f}")

def log_forecast_generation(forecasts):
    logger.info(f"Attack forecast generated: {len(forecasts)} assets")
    top_3 = sorted(forecasts, key=lambda x: x.attack_probability, reverse=True)[:3]
    for f in top_3:
        logger.info(f"  HIGH RISK: {f.asset_name} ({f.attack_probability:.2%})")

def log_mitigation_plan(plan):
    logger.info(f"Mitigation plan created: {len(plan.mitigations)} actions")
    logger.info(f"  Risk reduction: {plan.estimated_risk_reduction:.2%}")
    logger.info(f"  Total cost: ${plan.estimated_cost:,.0f}")
    logger.info(f"  Total downtime: {plan.estimated_downtime_hours:.1f} hours")
```

## 9. VALIDATION CHECKLIST

- [ ] All 8 modules imported without errors
- [ ] Database migrations executed successfully
- [ ] Neo4j graph initialized
- [ ] API routes accessible (GET /api/v1/resilience/ncri returns 200)
- [ ] Module initialization creates instances without exceptions
- [ ] Unit tests pass (min 80% coverage)
- [ ] Integration tests pass (data flows between modules)
- [ ] Performance targets met (NCRI < 5min, forecast < 10sec, etc.)
- [ ] Logging shows correct operation
- [ ] Dashboard displays NCRI, forecasts, and explanations

## 10. ROLLBACK PROCEDURE

If issues occur during integration:

```bash
# Remove differentiation routes
# Comment out: include_differentiation_routes(app)

# Remove module initializations
# Comment out all new module initialization code

# Drop new tables (if needed for clean slate)
# DROP TABLE ncri_history, incident_outcomes, mitigation_effectiveness, false_positive_log;

# Restart API server
# Existing IMMUNEX functionality remains intact
```

---

**Status**: Ready for production integration  
**Estimated Integration Time**: 4–6 hours  
**Risk Level**: Low (modular design, no changes to existing modules)
