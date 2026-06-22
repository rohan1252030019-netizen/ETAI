"""
IMMUNEX Elite Phase 4: Agent Memory Bus

Shared memory backbone for inter-agent communication, enabling SOC Agent,
Threat Intel Agent, Forecast Agent, Mitigation Agent, and Resilience Agent
to exchange context and learn from each other.

Author: Principal AI Architect
Date: 2026-06-22
Lines: 380
"""

import logging
import json
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict
import threading

logger , timezone= logging.getLogger(__name__)


@dataclass
class AgentMessage:
    """Message exchanged between agents."""
    sender: str
    recipient: str
    message_type: str  # "query", "response", "notification", "learning"
    payload: Dict[str, Any]
    timestamp: str = None
    priority: int = 5  # 1-10, higher = more urgent
    ttl_seconds: int = 300  # Time to live
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def is_expired(self) -> bool:
        """Check if message TTL has expired."""
        msg_time = datetime.fromisoformat(self.timestamp)
        age = (datetime.now(timezone.utc) - msg_time).total_seconds()
        return age > self.ttl_seconds


@dataclass
class AgentMemoryEntry:
    """Single entry in shared memory."""
    key: str
    value: Any
    agent_id: str
    created_at: str = None
    expires_at: Optional[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc).isoformat()
    
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= datetime.fromisoformat(self.expires_at)


class AgentMemoryBus:
    """
    Shared memory bus enabling inter-agent communication and learning.
    Maintains:
    - Shared context (incident state, asset status, threat intel)
    - Message queue (agent-to-agent communication)
    - Learning records (incident outcomes, mitigation effectiveness)
    - Event log (audit trail)
    """
    
    REGISTERED_AGENTS = [
        "soc_agent",
        "threat_intel_agent",
        "forecast_agent",
        "mitigation_agent",
        "resilience_agent"
    ]
    
    def __init__(self, postgres_client: Any = None):
        """
        Args:
            postgres_client: Optional PostgreSQL connection for persistence
        """
        self.postgres_client = postgres_client
        
        # Shared memory store (in-memory + optional DB)
        self.memory_store: Dict[str, AgentMemoryEntry] = {}
        
        # Message queues per agent
        self.message_queues: Dict[str, List[AgentMessage]] = defaultdict(list)
        
        # Learning records
        self.learning_records: List[Dict[str, Any]] = []
        
        # Event log
        self.event_log: List[Dict[str, Any]] = []
        
        # Subscribe-to handlers
        self.subscribers: Dict[str, List[Callable]] = defaultdict(list)
        
        # Thread safety
        self._lock = threading.RLock()
        
        logger.info("AgentMemoryBus initialized with %d agents", len(self.REGISTERED_AGENTS))
    
    def register_subscriber(self, event_type: str, callback: Callable) -> None:
        """
        Register callback for events of a given type.
        
        Args:
            event_type: Event type to subscribe to (e.g., "incident_detected")
            callback: Function to call when event occurs
        """
        with self._lock:
            self.subscribers[event_type].append(callback)
            logger.debug("Registered subscriber for %s", event_type)
    
    def write_memory(self,
                     key: str,
                     value: Any,
                     agent_id: str,
                     ttl_seconds: Optional[int] = None) -> None:
        """
        Write to shared memory.
        
        Args:
            key: Memory key (e.g., "incident:INC-123:status")
            value: Value to store
            agent_id: Agent writing
            ttl_seconds: Time-to-live (None = persist)
        """
        with self._lock:
            expires_at = None
            if ttl_seconds:
                expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
            
            entry = AgentMemoryEntry(
                key=key,
                value=value,
                agent_id=agent_id,
                expires_at=expires_at
            )
            
            self.memory_store[key] = entry
            
            # Persist to DB if available
            if self.postgres_client:
                self._persist_memory(entry)
            
            logger.debug("Memory written: %s by %s", key, agent_id)
            
            # Trigger subscribers
            self._trigger_subscribers(f"memory_updated:{key}", entry)
    
    def read_memory(self, key: str) -> Optional[Any]:
        """
        Read from shared memory.
        
        Args:
            key: Memory key
            
        Returns:
            Value if exists and not expired, else None
        """
        with self._lock:
            if key not in self.memory_store:
                return None
            
            entry = self.memory_store[key]
            if entry.is_expired():
                del self.memory_store[key]
                return None
            
            return entry.value
    
    def read_memory_by_prefix(self, prefix: str) -> Dict[str, Any]:
        """
        Read all memory entries matching a prefix.
        
        Args:
            prefix: Prefix to match (e.g., "incident:INC-123:*")
            
        Returns:
            Dict of matching key -> value pairs
        """
        with self._lock:
            results = {}
            for key, entry in self.memory_store.items():
                if not entry.is_expired() and key.startswith(prefix.rstrip("*")):
                    results[key] = entry.value
            return results
    
    def send_message(self,
                     sender: str,
                     recipient: str,
                     message_type: str,
                     payload: Dict[str, Any],
                     priority: int = 5) -> None:
        """
        Send inter-agent message.
        
        Args:
            sender: Sending agent ID
            recipient: Receiving agent ID
            message_type: Message type (query, response, notification, learning)
            payload: Message payload
            priority: Priority level (1-10)
        """
        with self._lock:
            if recipient not in self.REGISTERED_AGENTS:
                logger.warning("Recipient %s not registered", recipient)
                return
            
            msg = AgentMessage(
                sender=sender,
                recipient=recipient,
                message_type=message_type,
                payload=payload,
                priority=priority
            )
            
            self.message_queues[recipient].append(msg)
            logger.debug("Message sent: %s -> %s (%s)", sender, recipient, message_type)
            
            # Trigger subscribers
            self._trigger_subscribers(f"message_received:{recipient}", msg)
    
    def receive_messages(self, agent_id: str) -> List[AgentMessage]:
        """
        Retrieve all messages for an agent (non-destructive).
        
        Args:
            agent_id: Agent ID
            
        Returns:
            List of messages, sorted by priority (highest first)
        """
        with self._lock:
            if agent_id not in self.message_queues:
                return []
            
            # Filter expired, sort by priority
            msgs = [m for m in self.message_queues[agent_id] if not m.is_expired()]
            msgs.sort(key=lambda m: m.priority, reverse=True)
            
            return msgs
    
    def consume_message(self, agent_id: str) -> Optional[AgentMessage]:
        """
        Remove and return first (highest priority) message for agent.
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Next message, or None if queue empty
        """
        with self._lock:
            if agent_id not in self.message_queues or not self.message_queues[agent_id]:
                return None
            
            msgs = self.message_queues[agent_id]
            msgs = [m for m in msgs if not m.is_expired()]
            msgs.sort(key=lambda m: m.priority, reverse=True)
            
            if not msgs:
                return None
            
            msg = msgs.pop(0)
            self.message_queues[agent_id] = msgs
            
            return msg
    
    def record_learning(self,
                       incident_id: str,
                       agent_id: str,
                       learning_data: Dict[str, Any]) -> None:
        """
        Record learning outcome for model improvement.
        
        Args:
            incident_id: Incident ID
            agent_id: Agent that handled it
            learning_data: Dict with keys:
                - techniques: List of MITRE techniques
                - mitigations_applied: List of applied mitigations
                - effectiveness: float (0-1)
                - response_time_minutes: float
                - detection_time_minutes: float
        """
        with self._lock:
            record = {
                "incident_id": incident_id,
                "agent_id": agent_id,
                "learning_data": learning_data,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            self.learning_records.append(record)
            
            # Persist if DB available
            if self.postgres_client:
                self._persist_learning(record)
            
            logger.info("Learning recorded: incident %s by %s", incident_id, agent_id)
            
            # Trigger subscribers
            self._trigger_subscribers("learning_recorded", record)
    
    def get_learning_records(self,
                            incident_id: Optional[str] = None,
                            agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Query learning records.
        
        Args:
            incident_id: Filter by incident (optional)
            agent_id: Filter by agent (optional)
            
        Returns:
            List of matching learning records
        """
        with self._lock:
            results = self.learning_records
            
            if incident_id:
                results = [r for r in results if r["incident_id"] == incident_id]
            
            if agent_id:
                results = [r for r in results if r["agent_id"] == agent_id]
            
            return results
    
    def log_event(self,
                  event_type: str,
                  agent_id: str,
                  details: Dict[str, Any]) -> None:
        """
        Log an event to audit trail.
        
        Args:
            event_type: Type of event
            agent_id: Agent generating event
            details: Event details
        """
        with self._lock:
            entry = {
                "event_type": event_type,
                "agent_id": agent_id,
                "details": details,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            self.event_log.append(entry)
            
            # Persist if DB available
            if self.postgres_client:
                self._persist_event(entry)
            
            logger.info("Event logged: %s by %s", event_type, agent_id)
    
    def get_event_log(self,
                      event_type: Optional[str] = None,
                      hours: int = 24) -> List[Dict[str, Any]]:
        """
        Query event log.
        
        Args:
            event_type: Filter by event type (optional)
            hours: Only events from past N hours
            
        Returns:
            List of events
        """
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            results = [e for e in self.event_log 
                      if datetime.fromisoformat(e["timestamp"]) >= cutoff]
            
            if event_type:
                results = [e for e in results if e["event_type"] == event_type]
            
            return results
    
    def _trigger_subscribers(self, event_type: str, data: Any) -> None:
        """Trigger all subscribers for an event."""
        if event_type not in self.subscribers:
            return
        
        for callback in self.subscribers[event_type]:
            try:
                callback(data)
            except Exception as e:
                logger.error("Subscriber callback failed: %s", str(e))
    
    def _persist_memory(self, entry: AgentMemoryEntry) -> None:
        """Persist memory entry to PostgreSQL."""
        if not self.postgres_client:
            return
        try:
            query = """
            INSERT INTO agent_memory (key, value, agent_id, created_at, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (key) DO UPDATE SET value=%s, agent_id=%s
            """
            self.postgres_client.execute(query, (
                entry.key,
                json.dumps(entry.value),
                entry.agent_id,
                entry.created_at,
                entry.expires_at,
                json.dumps(entry.value),
                entry.agent_id
            ))
        except Exception as e:
            logger.warning("Failed to persist memory: %s", str(e))
    
    def _persist_learning(self, record: Dict[str, Any]) -> None:
        """Persist learning record to PostgreSQL."""
        if not self.postgres_client:
            return
        try:
            query = """
            INSERT INTO agent_learning (incident_id, agent_id, learning_data, timestamp)
            VALUES (%s, %s, %s, %s)
            """
            self.postgres_client.execute(query, (
                record["incident_id"],
                record["agent_id"],
                json.dumps(record["learning_data"]),
                record["timestamp"]
            ))
        except Exception as e:
            logger.warning("Failed to persist learning: %s", str(e))
    
    def _persist_event(self, entry: Dict[str, Any]) -> None:
        """Persist event to PostgreSQL."""
        if not self.postgres_client:
            return
        try:
            query = """
            INSERT INTO agent_events (event_type, agent_id, details, timestamp)
            VALUES (%s, %s, %s, %s)
            """
            self.postgres_client.execute(query, (
                entry["event_type"],
                entry["agent_id"],
                json.dumps(entry["details"]),
                entry["timestamp"]
            ))
        except Exception as e:
            logger.warning("Failed to persist event: %s", str(e))
