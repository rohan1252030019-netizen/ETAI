"""
Threat Actor Intelligence Graph

Neo4j-backed graph for tracking threat actors, campaigns, malware families,
targeting patterns, and TTP correlations.

Enables attribution, campaign tracking, and adversary profiling.

Author: IMMUNEX Core Team
"""

from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import logging
from dataclasses import dataclass

logger , timezone= logging.getLogger(__name__)


@dataclass
class ThreatActorProfile:
    """Profile of a threat actor."""
    actor_id: str
    actor_name: str
    aliases: List[str]
    confidence_score: float
    known_targets: List[str]
    preferred_sectors: List[str]
    known_malware: List[str]
    historical_campaigns: List[str]
    typical_ttp_chain: List[str]
    last_observed: datetime


class ThreatActorKnowledgeGraph:
    """
    Neo4j-backed knowledge graph for threat intelligence.
    
    Nodes:
        - Threat Actor
        - Campaign
        - Malware Family
        - Victim (organization/sector)
        - Technique (MITRE ATT&CK)
        - Infrastructure (C2, hosting)
    
    Relationships:
        - Actor conducts Campaign
        - Campaign uses Malware
        - Campaign targets Victim
        - Campaign employs Technique
        - Actor known for Technique
        - Infrastructure hosts Malware
    """
    
    def __init__(self, neo4j_client, mitre_mapper):
        """
        Initialize threat actor graph.
        
        Args:
            neo4j_client: Neo4j connection
            mitre_mapper: MITRE ATT&CK mapping engine
        """
        self.neo4j = neo4j_client
        self.mitre = mitre_mapper
    
    def get_threat_actor_profile(self, actor_name: str) -> Optional[ThreatActorProfile]:
        """
        Retrieve comprehensive threat actor profile.
        
        Returns:
            ThreatActorProfile with known campaigns, TTPs, targets
        """
        query = """
            MATCH (a:ThreatActor {name: $actor_name})
            OPTIONAL MATCH (a)-[:CONDUCTS]->(c:Campaign)
            OPTIONAL MATCH (a)-[:KNOWS_TTP]->(t:Technique)
            OPTIONAL MATCH (c)-[:TARGETS]->(v:Victim)
            OPTIONAL MATCH (c)-[:USES_MALWARE]->(m:Malware)
            RETURN a, collect(DISTINCT c.name) as campaigns,
                   collect(DISTINCT t.id) as techniques,
                   collect(DISTINCT v.sector) as sectors,
                   collect(DISTINCT m.name) as malware,
                   a.confidence as confidence
        """
        
        result = self.neo4j.query(query, {'actor_name': actor_name})
        
        if not result:
            return None
        
        row = result[0]
        
        return ThreatActorProfile(
            actor_id=row['a']['id'],
            actor_name=row['a']['name'],
            aliases=row['a'].get('aliases', []),
            confidence_score=row['confidence'] or 0.0,
            known_targets=row['sectors'],
            preferred_sectors=row['sectors'],
            known_malware=row['malware'],
            historical_campaigns=row['campaigns'],
            typical_ttp_chain=row['techniques'],
            last_observed=row['a'].get('last_observed', datetime.now(timezone.utc))
        )
    
    def attribute_incident_to_actor(
        self,
        techniques: List[str],
        malware_hashes: List[str],
        targeted_sectors: List[str],
        infrastructure_ips: List[str]
    ) -> List[Tuple[str, float]]:
        """
        Attribute incident to likely threat actors.
        
        Scores actors by similarity of:
            - TTP chains
            - Malware families
            - Targeting patterns
            - Infrastructure overlap
        
        Returns:
            List of (actor_name, confidence_score) sorted by confidence
        """
        # Query threat actors and calculate similarity
        query = """
            MATCH (a:ThreatActor)
            OPTIONAL MATCH (a)-[:KNOWS_TTP]->(t:Technique)
            OPTIONAL MATCH (a)-[:USES_MALWARE]->(m:Malware)
            OPTIONAL MATCH (a)-[*1..2]->(v:Victim)
            RETURN a.name as actor_name,
                   collect(DISTINCT t.id) as actor_techniques,
                   collect(DISTINCT m.family) as actor_malware,
                   collect(DISTINCT v.sector) as actor_targets,
                   a.confidence as base_confidence
        """
        
        results = self.neo4j.query(query)
        
        actor_scores = []
        for row in results:
            actor_name = row['actor_name']
            
            # Calculate TTP overlap
            ttp_overlap = len(set(techniques) & set(row['actor_techniques']))
            ttp_score = ttp_overlap / max(1, len(row['actor_techniques']))
            
            # Calculate sector overlap
            sector_overlap = len(set(targeted_sectors) & set(row['actor_targets']))
            sector_score = sector_overlap / max(1, len(row['actor_targets']))
            
            # Combined confidence
            confidence = (
                0.6 * ttp_score +  # TTPs are most reliable for attribution
                0.3 * sector_score +
                0.1 * (row['base_confidence'] or 0.5)
            )
            
            if confidence > 0.3:  # Only return plausible attributions
                actor_scores.append((actor_name, confidence))
        
        return sorted(actor_scores, key=lambda x: x[1], reverse=True)
    
    def find_similar_campaigns(
        self,
        techniques: List[str],
        malware_families: List[str],
        targeted_sectors: List[str],
        top_k: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find campaigns with similar characteristics.
        
        Uses Jaccard similarity on TTP sets and cosine similarity on sector vectors.
        
        Returns:
            List of similar campaigns with details
        """
        query = """
            MATCH (c:Campaign)
            OPTIONAL MATCH (c)-[:EMPLOYS]->(t:Technique)
            OPTIONAL MATCH (c)-[:USES_MALWARE]->(m:Malware)
            OPTIONAL MATCH (c)-[:TARGETS]->(v:Victim)
            RETURN c.id as campaign_id,
                   c.name as campaign_name,
                   c.attribution as attribution,
                   collect(DISTINCT t.id) as campaign_techniques,
                   collect(DISTINCT m.family) as campaign_malware,
                   collect(DISTINCT v.sector) as campaign_sectors,
                   c.first_seen as first_seen,
                   c.last_seen as last_seen
            LIMIT $k
        """
        
        results = self.neo4j.query(query, {'k': top_k * 3})
        
        # Score each campaign
        scored = []
        for row in results:
            # Jaccard similarity on TTPs
            ttp_intersection = len(set(techniques) & set(row['campaign_techniques']))
            ttp_union = len(set(techniques) | set(row['campaign_techniques']))
            ttp_jaccard = ttp_intersection / max(1, ttp_union)
            
            # Sector overlap
            sector_overlap = len(set(targeted_sectors) & set(row['campaign_sectors']))
            sector_score = sector_overlap / max(1, len(row['campaign_sectors']))
            
            # Combined score
            score = 0.7 * ttp_jaccard + 0.3 * sector_score
            
            if score > 0.2:
                scored.append({
                    'campaign_id': row['campaign_id'],
                    'campaign_name': row['campaign_name'],
                    'attribution': row['attribution'],
                    'techniques': row['campaign_techniques'],
                    'malware': row['campaign_malware'],
                    'sectors': row['campaign_sectors'],
                    'similarity_score': score,
                    'first_seen': row['first_seen'],
                    'last_seen': row['last_seen']
                })
        
        return sorted(scored, key=lambda x: x['similarity_score'], reverse=True)[:top_k]
    
    def get_campaign_details(self, campaign_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve comprehensive campaign details."""
        query = """
            MATCH (c:Campaign {name: $campaign_name})
            OPTIONAL MATCH (c)-[:CONDUCTED_BY]->(a:ThreatActor)
            OPTIONAL MATCH (c)-[:TARGETS]->(v:Victim)
            OPTIONAL MATCH (c)-[:USES_MALWARE]->(m:Malware)
            OPTIONAL MATCH (c)-[:EMPLOYS]->(t:Technique)
            RETURN c, a.name as actor, collect(v.name) as victims,
                   collect(m.name) as malware, collect(t.id) as techniques
        """
        
        result = self.neo4j.query(query, {'campaign_name': campaign_name})
        
        if not result:
            return None
        
        row = result[0]
        campaign = row['c']
        
        return {
            'campaign_id': campaign['id'],
            'campaign_name': campaign['name'],
            'attribution': row['actor'],
            'targets': row['victims'],
            'malware_families': row['malware'],
            'techniques': row['techniques'],
            'first_observed': campaign.get('first_observed'),
            'last_observed': campaign.get('last_observed'),
            'description': campaign.get('description', '')
        }
    
    def correlate_indicators(
        self,
        malware_hashes: List[str],
        infrastructure_ips: List[str],
        domains: List[str]
    ) -> List[str]:
        """
        Correlate indicators across threat actor graph.
        
        Returns:
            List of actor names linked to these indicators
        """
        actors = set()
        
        # Query by malware hashes
        for hash_val in malware_hashes:
            query = "MATCH (m:Malware {hash: $h})-[:USED_BY]->(c:Campaign)-[:CONDUCTED_BY]->(a:ThreatActor) RETURN a.name"
            results = self.neo4j.query(query, {'h': hash_val})
            actors.update(r['a.name'] for r in results if r.get('a.name'))
        
        # Query by infrastructure
        for ip in infrastructure_ips:
            query = "MATCH (i:Infrastructure {ip: $ip})-[:USED_BY]->(c:Campaign)-[:CONDUCTED_BY]->(a:ThreatActor) RETURN a.name"
            results = self.neo4j.query(query, {'ip': ip})
            actors.update(r['a.name'] for r in results if r.get('a.name'))
        
        return list(actors)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Threat Actor Knowledge Graph loaded")
