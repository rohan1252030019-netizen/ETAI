"""
IMMUNEX Elite Phase 5: Streaming Threat Fusion

Real-time ingestion and correlation of security events from multiple sources:
- Syslog (IDS/IPS)
- Zeek (network IDS)
- Suricata (IDS/IPS)
- CloudTrail (AWS/GCP/Azure audit)
- EDR (endpoint detection and response)

Fuses heterogeneous events into unified threat stream with risk scoring.

Author: Principal AI Architect
Date: 2026-06-22
Lines: 450
"""

import logging
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib

logger , timezone= logging.getLogger(__name__)


@dataclass
class ThreatEvent:
    """Unified threat event from any source."""
    event_id: str
    source: str  # "syslog", "zeek", "suricata", "cloudtrail", "edr"
    event_type: str  # "alert", "flow", "detection", "audit", "detection"
    timestamp: str
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    signature: Optional[str] = None
    payload: Dict[str, Any] = None
    
    # Enriched fields
    asset_id: Optional[str] = None
    criticality: Optional[str] = None
    technique: Optional[str] = None  # MITRE technique
    risk_score: float = 0.0
    correlated_events: List[str] = None
    
    def __post_init__(self):
        if self.payload is None:
            self.payload = {}
        if self.correlated_events is None:
            self.correlated_events = []


class StreamingThreatFusion:
    """
    Consumes security events from multiple sources, correlates them,
    enriches with threat intelligence, and scores risk.
    """
    
    # Known signatures to MITRE mapping
    SIGNATURE_MAPPING = {
        "SQL Injection": ["T1190"],  # Exploit Public-Facing Application
        "XSS": ["T1190"],
        "Command Execution": ["T1059"],  # Command and Scripting Interpreter
        "Lateral Movement": ["T1570"],  # Lateral Tool Transfer
        "Privilege Escalation": ["T1548"],  # Abuse Elevation Control Mechanism
        "Credential Dumping": ["T1110"],  # Brute Force
        "Data Exfiltration": ["T1041"],  # Exfiltration Over C2 Channel
        "C2 Communication": ["T1071"],  # Application Layer Protocol
    }
    
    def __init__(self,
                 attack_graph: Any = None,
                 cve_db: Any = None,
                 threat_actor_db: Any = None,
                 postgres_client: Any = None):
        """
        Args:
            attack_graph: Attack graph for enrichment
            cve_db: CVE database for risk scoring
            threat_actor_db: Threat actor patterns
            postgres_client: PostgreSQL for persistence
        """
        self.attack_graph = attack_graph
        self.cve_db = cve_db
        self.threat_actor_db = threat_actor_db
        self.postgres_client = postgres_client
        
        # Event buffer for correlation
        self.event_buffer: Dict[str, ThreatEvent] = {}
        self.correlation_window_seconds = 300  # 5 minutes
        
        # Correlation statistics
        self.correlation_stats = defaultdict(int)
        
        logger.info("StreamingThreatFusion initialized")
    
    def ingest_syslog(self, syslog_entry: Dict[str, Any]) -> Optional[ThreatEvent]:
        """
        Parse syslog IDS/IPS alert.
        
        Expected format:
        {
            "timestamp": "2026-06-22T10:15:30Z",
            "host": "192.168.1.50",
            "signature": "SQL Injection",
            "src_ip": "10.0.1.100",
            "dst_ip": "192.168.1.50",
            "port": 443
        }
        """
        try:
            timestamp = syslog_entry.get("timestamp", datetime.now(timezone.utc).isoformat())
            host = syslog_entry.get("host")
            signature = syslog_entry.get("signature", "Unknown")
            src_ip = syslog_entry.get("src_ip")
            dst_ip = syslog_entry.get("dst_ip")
            
            event_id = self._generate_event_id(f"syslog:{host}:{signature}:{timestamp}")
            
            event = ThreatEvent(
                event_id=event_id,
                source="syslog",
                event_type="alert",
                timestamp=timestamp,
                host=host,
                src_ip=src_ip,
                dst_ip=dst_ip,
                port=syslog_entry.get("port"),
                signature=signature,
                payload=syslog_entry
            )
            
            return self._enrich_and_store(event)
        except Exception as e:
            logger.warning("Error ingesting syslog: %s", str(e))
            return None
    
    def ingest_zeek(self, zeek_entry: Dict[str, Any]) -> Optional[ThreatEvent]:
        """
        Parse Zeek network flow.
        
        Expected format:
        {
            "timestamp": "2026-06-22T10:15:30Z",
            "src_ip": "10.0.1.100",
            "dst_ip": "192.168.1.50",
            "src_port": 51234,
            "dst_port": 443,
            "protocol": "tcp",
            "service": "https",
            "bytes_sent": 4096,
            "bytes_received": 2048
        }
        """
        try:
            timestamp = zeek_entry.get("timestamp", datetime.now(timezone.utc).isoformat())
            src_ip = zeek_entry.get("src_ip")
            dst_ip = zeek_entry.get("dst_ip")
            dst_port = zeek_entry.get("dst_port")
            
            event_id = self._generate_event_id(f"zeek:{src_ip}:{dst_ip}:{dst_port}:{timestamp}")
            
            event = ThreatEvent(
                event_id=event_id,
                source="zeek",
                event_type="flow",
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                port=dst_port,
                protocol=zeek_entry.get("protocol"),
                payload=zeek_entry
            )
            
            return self._enrich_and_store(event)
        except Exception as e:
            logger.warning("Error ingesting Zeek: %s", str(e))
            return None
    
    def ingest_suricata(self, suricata_entry: Dict[str, Any]) -> Optional[ThreatEvent]:
        """
        Parse Suricata alert.
        
        Expected format:
        {
            "timestamp": "2026-06-22T10:15:30Z",
            "src_ip": "10.0.1.100",
            "dst_ip": "192.168.1.50",
            "src_port": 12345,
            "dst_port": 443,
            "protocol": "tcp",
            "alert": {"signature": "ET MALWARE Suspicious User-Agent"},
            "flow": {...}
        }
        """
        try:
            timestamp = suricata_entry.get("timestamp", datetime.now(timezone.utc).isoformat())
            src_ip = suricata_entry.get("src_ip")
            dst_ip = suricata_entry.get("dst_ip")
            
            alert_info = suricata_entry.get("alert", {})
            signature = alert_info.get("signature", "Unknown")
            
            event_id = self._generate_event_id(f"suricata:{src_ip}:{dst_ip}:{signature}:{timestamp}")
            
            event = ThreatEvent(
                event_id=event_id,
                source="suricata",
                event_type="detection",
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                port=suricata_entry.get("dst_port"),
                protocol=suricata_entry.get("protocol"),
                signature=signature,
                payload=suricata_entry
            )
            
            return self._enrich_and_store(event)
        except Exception as e:
            logger.warning("Error ingesting Suricata: %s", str(e))
            return None
    
    def ingest_cloudtrail(self, cloudtrail_entry: Dict[str, Any]) -> Optional[ThreatEvent]:
        """
        Parse CloudTrail audit log.
        
        Expected format:
        {
            "eventTime": "2026-06-22T10:15:30Z",
            "eventName": "CreateAccessKey",
            "userIdentity": {"principalId": "AIDAI..."},
            "sourceIPAddress": "10.0.1.100",
            "userAgent": "AWS CLI/2.13.0"
        }
        """
        try:
            timestamp = cloudtrail_entry.get("eventTime", datetime.now(timezone.utc).isoformat())
            event_name = cloudtrail_entry.get("eventName", "Unknown")
            src_ip = cloudtrail_entry.get("sourceIPAddress")
            
            event_id = self._generate_event_id(f"cloudtrail:{event_name}:{src_ip}:{timestamp}")
            
            event = ThreatEvent(
                event_id=event_id,
                source="cloudtrail",
                event_type="audit",
                timestamp=timestamp,
                src_ip=src_ip,
                signature=event_name,
                payload=cloudtrail_entry
            )
            
            return self._enrich_and_store(event)
        except Exception as e:
            logger.warning("Error ingesting CloudTrail: %s", str(e))
            return None
    
    def ingest_edr(self, edr_entry: Dict[str, Any]) -> Optional[ThreatEvent]:
        """
        Parse EDR alert.
        
        Expected format:
        {
            "timestamp": "2026-06-22T10:15:30Z",
            "hostname": "WORKSTATION-42",
            "process_name": "rundll32.exe",
            "process_cmd": "rundll32.exe shell32.dll",
            "parent_process": "explorer.exe",
            "file_hash": "abc123...",
            "detection": "Suspicious Process Execution"
        }
        """
        try:
            timestamp = edr_entry.get("timestamp", datetime.now(timezone.utc).isoformat())
            hostname = edr_entry.get("hostname")
            detection = edr_entry.get("detection", "Unknown")
            
            event_id = self._generate_event_id(f"edr:{hostname}:{detection}:{timestamp}")
            
            event = ThreatEvent(
                event_id=event_id,
                source="edr",
                event_type="detection",
                timestamp=timestamp,
                host=hostname,
                signature=detection,
                payload=edr_entry
            )
            
            return self._enrich_and_store(event)
        except Exception as e:
            logger.warning("Error ingesting EDR: %s", str(e))
            return None
    
    def _enrich_and_store(self, event: ThreatEvent) -> ThreatEvent:
        """Enrich event with threat intel and store in buffer."""
        # Map signature to MITRE technique
        for sig_pattern, techniques in self.SIGNATURE_MAPPING.items():
            if sig_pattern.lower() in (event.signature or "").lower():
                event.technique = techniques[0]
                break
        
        # Compute risk score
        event.risk_score = self._compute_risk_score(event)
        
        # Correlate with similar events
        correlated = self._find_correlated_events(event)
        event.correlated_events = correlated
        
        # Store in buffer
        self.event_buffer[event.event_id] = event
        
        # Cleanup old events
        self._cleanup_buffer()
        
        # Persist if DB available
        if self.postgres_client:
            self._persist_event(event)
        
        logger.info("Event ingested: %s (source=%s, risk=%.2f)",
                   event.event_id, event.source, event.risk_score)
        
        return event
    
    def _compute_risk_score(self, event: ThreatEvent) -> float:
        """Compute risk score for event (0-1)."""
        base_score = 0.5
        
        # Severity based on source and type
        source_weights = {
            "edr": 0.9,
            "suricata": 0.7,
            "syslog": 0.6,
            "zeek": 0.4,
            "cloudtrail": 0.5
        }
        base_score *= source_weights.get(event.source, 0.5)
        
        # Boost for known malicious patterns
        if event.signature:
            malicious_keywords = ["malware", "trojan", "ransomware", "exploit", "backdoor"]
            if any(kw in event.signature.lower() for kw in malicious_keywords):
                base_score *= 1.5
        
        # Boost if correlates with other events
        if event.correlated_events:
            base_score *= (1.0 + 0.1 * len(event.correlated_events))
        
        return min(1.0, base_score)
    
    def _find_correlated_events(self, event: ThreatEvent) -> List[str]:
        """Find events that correlate with this one."""
        correlated = []
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.correlation_window_seconds)
        
        for other_id, other_event in self.event_buffer.items():
            if other_id == event.event_id:
                continue
            
            # Check timestamp
            other_time = datetime.fromisoformat(other_event.timestamp)
            if other_time < cutoff:
                continue
            
            # Check correlation criteria
            score = 0.0
            
            # Same source IP
            if event.src_ip and other_event.src_ip == event.src_ip:
                score += 0.4
            
            # Same destination IP
            if event.dst_ip and other_event.dst_ip == event.dst_ip:
                score += 0.3
            
            # Same host
            if event.host and other_event.host == event.host:
                score += 0.3
            
            # Same technique
            if event.technique and other_event.technique == event.technique:
                score += 0.3
            
            if score > 0.5:
                correlated.append(other_id)
                self.correlation_stats[(event.source, other_event.source)] += 1
        
        return correlated
    
    def _cleanup_buffer(self) -> None:
        """Remove old events from buffer."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.correlation_window_seconds * 2)
        
        expired_ids = []
        for event_id, event in self.event_buffer.items():
            event_time = datetime.fromisoformat(event.timestamp)
            if event_time < cutoff:
                expired_ids.append(event_id)
        
        for event_id in expired_ids:
            del self.event_buffer[event_id]
    
    def get_threat_stream(self, 
                         min_risk_score: float = 0.0,
                         limit: int = 100) -> List[ThreatEvent]:
        """
        Get unified threat stream sorted by risk and recency.
        
        Args:
            min_risk_score: Filter by minimum risk score
            limit: Maximum events to return
            
        Returns:
            List of ThreatEvent sorted by (risk desc, timestamp desc)
        """
        events = [e for e in self.event_buffer.values() 
                 if e.risk_score >= min_risk_score]
        
        events.sort(key=lambda e: (e.risk_score, e.timestamp), reverse=True)
        return events[:limit]
    
    def get_correlated_events(self, event_id: str) -> List[ThreatEvent]:
        """Get all events correlated with a given event."""
        if event_id not in self.event_buffer:
            return []
        
        event = self.event_buffer[event_id]
        correlated = [self.event_buffer[cid] for cid in event.correlated_events
                     if cid in self.event_buffer]
        
        return correlated
    
    def _generate_event_id(self, text: str) -> str:
        """Generate deterministic event ID."""
        return hashlib.sha256(text.encode()).hexdigest()[:16]
    
    def _persist_event(self, event: ThreatEvent) -> None:
        """Persist event to PostgreSQL."""
        if not self.postgres_client:
            return
        
        try:
            query = """
            INSERT INTO threat_stream 
            (event_id, source, event_type, timestamp, host, src_ip, dst_ip, 
             port, protocol, signature, risk_score, correlated_events, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            self.postgres_client.execute(query, (
                event.event_id,
                event.source,
                event.event_type,
                event.timestamp,
                event.host,
                event.src_ip,
                event.dst_ip,
                event.port,
                event.protocol,
                event.signature,
                event.risk_score,
                json.dumps(event.correlated_events),
                json.dumps(event.payload)
            ))
        except Exception as e:
            logger.warning("Failed to persist threat event: %s", str(e))
    
    def get_correlation_stats(self) -> Dict[Tuple[str, str], int]:
        """Get correlation statistics between sources."""
        return dict(self.correlation_stats)
