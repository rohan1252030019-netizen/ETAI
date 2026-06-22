"""
Cyber Learning Memory System

Continuously learns from incidents, simulations, playbook outcomes,
and analyst feedback to improve risk models and recommendations.

Uses FAISS for semantic search and feedback loops for model adaptation.

Author: IMMUNEX Core Team
"""

from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import logging
from dataclasses import dataclass

logger , timezone= logging.getLogger(__name__)


@dataclass
class IncidentOutcome:
    """Recorded incident outcome for learning."""
    incident_id: str
    techniques_used: List[str]
    mitigations_applied: List[str]
    effectiveness_rating: float  # 0-1, higher = more effective response
    detection_time_minutes: float
    response_time_minutes: float
    recovered: bool
    recovery_time_minutes: float
    analyst_notes: str
    recorded_at: datetime


class CyberLearningMemory:
    """
    Continuous learning system that improves from every incident and simulation.
    
    Capabilities:
        - Store incident outcomes and lessons learned
        - Find similar past incidents for reference
        - Recommend response actions based on history
        - Update risk models from feedback
        - Track false positives/negatives
    """
    
    def __init__(self, postgres_client, incident_store, faiss_index=None):
        """
        Initialize learning memory.
        
        Args:
            postgres_client: PostgreSQL for outcome storage
            incident_store: Historical incident database
            faiss_index: Optional FAISS index for semantic search
        """
        self.postgres = postgres_client
        self.incident_store = incident_store
        self.faiss = faiss_index
    
    def record_incident_outcome(
        self,
        incident_id: str,
        techniques_used: List[str],
        mitigations_applied: List[str],
        effectiveness_rating: float,
        detection_time_minutes: float,
        response_time_minutes: float,
        recovered: bool,
        recovery_time_minutes: float,
        analyst_notes: str
    ) -> Dict[str, Any]:
        """
        Record incident outcome for learning.
        
        Updates model weights and risk assessments based on outcome.
        """
        outcome = IncidentOutcome(
            incident_id=incident_id,
            techniques_used=techniques_used,
            mitigations_applied=mitigations_applied,
            effectiveness_rating=effectiveness_rating,
            detection_time_minutes=detection_time_minutes,
            response_time_minutes=response_time_minutes,
            recovered=recovered,
            recovery_time_minutes=recovery_time_minutes,
            analyst_notes=analyst_notes,
            recorded_at=datetime.now(timezone.utc)
        )
        
        # Store in database
        self._store_outcome(outcome)
        
        # Update technique risk weights
        for technique in techniques_used:
            self._update_technique_risk_weight(technique, effectiveness_rating)
        
        # Update mitigation effectiveness scores
        for mitigation in mitigations_applied:
            self._update_mitigation_effectiveness(mitigation, effectiveness_rating)
        
        # Generate embedding for semantic search
        if self.faiss:
            embedding = self._embed_incident_outcome(outcome)
            self.faiss.add_vector(incident_id, embedding)
        
        logger.info(f"Recorded outcome for incident {incident_id}")
        
        return {
            'status': 'recorded',
            'incident_id': incident_id,
            'updates': {
                'technique_weights_updated': len(techniques_used),
                'mitigation_scores_updated': len(mitigations_applied)
            }
        }
    
    def query_similar_incidents(
        self,
        incident_characteristics: Dict[str, Any],
        top_k: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find similar past incidents for analyst reference.
        
        Uses FAISS semantic search if available, else SQL similarity.
        
        Returns:
            List of similar incidents with outcomes and recommendations
        """
        if not self.faiss:
            return self._query_similar_incidents_sql(incident_characteristics, top_k)
        
        # FAISS semantic search
        query_embedding = self._embed_incident_characteristics(incident_characteristics)
        similar_ids = self.faiss.search(query_embedding, top_k)
        
        similar_incidents = []
        for incident_id in similar_ids:
            outcome = self._get_outcome(incident_id)
            if outcome:
                similar_incidents.append({
                    'incident_id': incident_id,
                    'techniques': outcome['techniques_used'],
                    'effective_mitigations': outcome['mitigations_applied'],
                    'effectiveness_rating': outcome['effectiveness_rating'],
                    'detection_time_minutes': outcome['detection_time_minutes'],
                    'response_time_minutes': outcome['response_time_minutes'],
                    'analyst_notes': outcome['analyst_notes']
                })
        
        return similar_incidents
    
    def recommend_response_actions(
        self,
        incident_type: str,
        techniques: List[str],
        affected_assets: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Recommend response actions based on historical outcomes.
        
        Returns:
            List of recommended mitigations ranked by effectiveness
        """
        # Query incidents with similar techniques
        similar_outcomes = self._query_outcomes_by_techniques(techniques)
        
        # Aggregate recommendations by effectiveness
        mitigation_scores = {}
        for outcome in similar_outcomes:
            for mitigation in outcome['mitigations_applied']:
                if mitigation not in mitigation_scores:
                    mitigation_scores[mitigation] = []
                mitigation_scores[mitigation].append(outcome['effectiveness_rating'])
        
        # Calculate average effectiveness
        recommendations = [
            {
                'mitigation': mitigation,
                'effectiveness_score': sum(scores) / len(scores),
                'frequency_in_similar_incidents': len(scores),
                'estimated_recovery_time_minutes': self._estimate_recovery_time(
                    mitigation, affected_assets
                )
            }
            for mitigation, scores in mitigation_scores.items()
        ]
        
        return sorted(recommendations, key=lambda x: x['effectiveness_score'], reverse=True)
    
    def update_risk_model_from_feedback(self, feedback: Dict[str, Any]) -> None:
        """
        Update risk models based on analyst feedback.
        
        Handles:
            - Forecast accuracy corrections
            - False positive/negative marking
            - Rule weight adjustments
        """
        if feedback.get('is_false_positive'):
            self._record_false_positive(feedback)
        
        if feedback.get('forecast_accuracy') is not None:
            self._adjust_forecast_weights(feedback)
    
    def _store_outcome(self, outcome: IncidentOutcome) -> None:
        """Store outcome in PostgreSQL."""
        # Placeholder: would execute SQL INSERT
        logger.debug(f"Stored outcome for {outcome.incident_id}")
    
    def _update_technique_risk_weight(self, technique: str, effectiveness: float) -> None:
        """
        Update risk weight for technique based on mitigation effectiveness.
        
        If technique was stopped quickly (high effectiveness), reduce weight.
        If it caused major damage (low effectiveness), increase weight.
        """
        # Placeholder: would update technique_risk_weights table
        logger.debug(f"Updated weight for {technique} (effectiveness: {effectiveness})")
    
    def _update_mitigation_effectiveness(self, mitigation: str, effectiveness: float) -> None:
        """Update effectiveness score for mitigation."""
        # Placeholder: would update mitigation_effectiveness table
        pass
    
    def _embed_incident_outcome(self, outcome: IncidentOutcome) -> List[float]:
        """Generate vector embedding for semantic search."""
        # Placeholder: would use sentence-transformer or similar
        return [0.0] * 768  # 768-dim embedding
    
    def _embed_incident_characteristics(self, characteristics: Dict) -> List[float]:
        """Generate query embedding."""
        return [0.0] * 768
    
    def _query_similar_incidents_sql(self, characteristics: Dict, top_k: int) -> List[Dict]:
        """SQL-based similarity query (fallback if FAISS unavailable)."""
        return []
    
    def _get_outcome(self, incident_id: str) -> Optional[Dict]:
        """Retrieve stored outcome."""
        return None
    
    def _query_outcomes_by_techniques(self, techniques: List[str]) -> List[Dict]:
        """Query outcomes involving similar techniques."""
        return []
    
    def _estimate_recovery_time(self, mitigation: str, affected_assets: List[str]) -> float:
        """Estimate recovery time in minutes."""
        return 60.0
    
    def _record_false_positive(self, feedback: Dict) -> None:
        """Record false positive for alert tuning."""
        pass
    
    def _adjust_forecast_weights(self, feedback: Dict) -> None:
        """Adjust forecast model weights based on accuracy feedback."""
        pass


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Cyber Learning Memory loaded")
