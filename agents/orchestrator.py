"""
IMMUNEX Phase 3 — Multi-Agent Orchestration System
=====================================================
Provides a cooperative multi-agent architecture for autonomous threat
detection, attribution, MITRE mapping, CVE prioritisation, attack-path
prediction, digital-twin simulation, SOAR response, and SOC co-pilot
query handling.

Architecture:
  ┌──────────────────────────────────────────────────────┐
  │               MultiAgentOrchestrator                 │
  │  ┌────────────┐  ┌────────────┐  ┌────────────────┐ │
  │  │ EventBus   │  │ SharedMem  │  │ Agent Registry │ │
  │  └────────────┘  └────────────┘  └────────────────┘ │
  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ... │
  │  │Anoml │ │Attrib│ │MITRE │ │CVE   │ │Path  │     │
  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘     │
  └──────────────────────────────────────────────────────┘

Each agent is a self-contained async processor that reads from the
event bus, updates shared memory, and publishes results downstream.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import random
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import networkx as nx
from pydantic import BaseModel, Field

from utils.logger import log


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Pydantic Models
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class AgentResult(BaseModel):
    """Standardised result envelope returned by every agent."""

    agent_id: str
    agent_type: str
    status: str = "success"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    processing_time_ms: float = 0.0


class PipelineResult(BaseModel):
    """Aggregated result from a full threat-processing pipeline run."""

    pipeline_id: str
    started_at: str
    completed_at: str = ""
    stages_completed: List[str] = Field(default_factory=list)
    agent_results: Dict[str, AgentResult] = Field(default_factory=dict)
    overall_risk_score: float = 0.0
    recommended_actions: List[str] = Field(default_factory=list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Agent Event Bus
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class AgentEventBus:
    """
    Asynchronous publish-subscribe event bus for inter-agent communication.

    Internally uses per-topic ``asyncio.Queue`` instances so that
    subscribers consume events in FIFO order without blocking publishers.
    """

    def __init__(self, max_queue_size: int = 10_000) -> None:
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._queues: Dict[str, asyncio.Queue] = {}
        self._max_queue_size = max_queue_size
        self._event_count: int = 0
        log.info("AgentEventBus initialised", max_queue_size=max_queue_size)

    def subscribe(self, topic: str, callback: Callable) -> None:
        """Register *callback* as a subscriber to *topic*."""
        self._subscribers[topic].append(callback)
        if topic not in self._queues:
            self._queues[topic] = asyncio.Queue(maxsize=self._max_queue_size)
        log.debug("EventBus subscription added", topic=topic, callback=callback.__qualname__)

    async def publish(self, topic: str, event: dict) -> None:
        """Publish *event* to all callbacks registered under *topic*."""
        self._event_count += 1
        event.setdefault("_event_id", str(uuid.uuid4())[:8])
        event.setdefault("_topic", topic)
        event.setdefault("_published_at", datetime.now(timezone.utc).isoformat())

        for cb in self._subscribers.get(topic, []):
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(event)
                else:
                    cb(event)
            except Exception as exc:
                log.error("EventBus callback error", topic=topic, error=str(exc))

        # Also enqueue for polling consumers
        if topic in self._queues:
            try:
                self._queues[topic].put_nowait(event)
            except asyncio.QueueFull:
                log.warning("EventBus queue full, dropping oldest event", topic=topic)
                try:
                    self._queues[topic].get_nowait()
                    self._queues[topic].put_nowait(event)
                except Exception:
                    pass

    async def consume(self, topic: str, timeout: float = 5.0) -> Optional[dict]:
        """Consume the next event from *topic* (blocking up to *timeout* seconds)."""
        if topic not in self._queues:
            self._queues[topic] = asyncio.Queue(maxsize=self._max_queue_size)
        try:
            return await asyncio.wait_for(self._queues[topic].get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    @property
    def event_count(self) -> int:
        return self._event_count


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Shared Memory
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class SharedMemory:
    """
    Thread-safe key-value store shared across all agents in an orchestrator.

    Supports atomic set/get/delete with namespace-prefixed keys so that
    agents can maintain scoped state without collisions.
    """

    def __init__(self) -> None:
        self._store: Dict[str, Any] = {}
        self._lock = threading.RLock()
        log.info("SharedMemory initialised")

    def set(self, key: str, value: Any) -> None:
        """Set *key* to *value* atomically."""
        with self._lock:
            self._store[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Return the value for *key*, or *default* if absent."""
        with self._lock:
            return self._store.get(key, default)

    def delete(self, key: str) -> bool:
        """Remove *key*; returns ``True`` if *key* existed."""
        with self._lock:
            return self._store.pop(key, None) is not None

    def list_keys(self, prefix: str = "") -> List[str]:
        """Return all keys that start with *prefix*."""
        with self._lock:
            if not prefix:
                return list(self._store.keys())
            return [k for k in self._store if k.startswith(prefix)]

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._store.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._store)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Base Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class BaseAgent(ABC):
    """
    Abstract base class for all IMMUNEX multi-agent system agents.

    Every concrete agent MUST implement ``async process(event)`` which
    receives a raw event dict and returns an ``AgentResult`` dict.
    """

    def __init__(
        self,
        agent_id: str,
        agent_type: str,
        event_bus: Optional[AgentEventBus] = None,
        shared_memory: Optional[SharedMemory] = None,
    ) -> None:
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.status: str = "idle"
        self.memory: Dict[str, Any] = {}
        self._event_bus = event_bus
        self._shared_memory = shared_memory
        self._events_processed: int = 0
        self._errors: int = 0
        self._created_at: str = datetime.now(timezone.utc).isoformat()
        log.info("Agent created", agent_id=agent_id, agent_type=agent_type)

    @abstractmethod
    async def process(self, event: dict) -> dict:
        """Process an incoming event and return a result dict."""
        ...

    def health_check(self) -> bool:
        """Return ``True`` if the agent is operational."""
        return self.status not in ("error", "stopped")

    async def _safe_process(self, event: dict) -> AgentResult:
        """Wrap ``process`` with timing, error handling, and status tracking."""
        self.status = "processing"
        t0 = time.perf_counter()
        try:
            data = await self.process(event)
            elapsed = (time.perf_counter() - t0) * 1000
            self._events_processed += 1
            self.status = "idle"
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status="success",
                data=data,
                processing_time_ms=round(elapsed, 2),
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            self._errors += 1
            self.status = "error"
            log.error("Agent processing failed", agent_id=self.agent_id, error=str(exc))
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status="error",
                errors=[str(exc)],
                processing_time_ms=round(elapsed, 2),
            )

    def stats(self) -> dict:
        """Return operational statistics for this agent."""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "status": self.status,
            "events_processed": self._events_processed,
            "errors": self._errors,
            "healthy": self.health_check(),
            "created_at": self._created_at,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Agent 1 — Behavioral Anomaly Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Feature weights for the inline IsolationForest-style scorer
_FEATURE_WEIGHTS: Dict[str, float] = {
    "failed_logins": 0.30,
    "bytes_sent": 0.15,
    "bytes_received": 0.10,
    "packet_count": 0.10,
    "connection_duration": 0.05,
    "port_scan_indicator": 0.25,
    "privilege_escalation_indicator": 0.20,
    "unusual_hour": 0.15,
    "geo_anomaly": 0.10,
}

# Known-malicious event types that immediately push scores up
_HIGH_RISK_EVENT_TYPES: Set[str] = {
    "Brute_Force_Login", "Data_Exfiltration", "PowerShell_Execution",
    "Suspicious_Process_Spawn", "DNS_Tunneling", "Port_Scan",
    "Ransomware_Encryption", "Credential_Dump",
}


class BehavioralAnomalyAgent(BaseAgent):
    """
    Evaluates raw telemetry for behavioural anomalies using an
    IsolationForest-inspired scoring heuristic.

    Input : raw telemetry dict with fields like ``failed_logins``,
            ``bytes_sent``, ``event_type``, ``src_ip``, etc.
    Output: anomaly classification with normalised score ∈ [0, 1].
    """

    def __init__(
        self,
        event_bus: Optional[AgentEventBus] = None,
        shared_memory: Optional[SharedMemory] = None,
    ) -> None:
        super().__init__(
            agent_id=f"anomaly-{uuid.uuid4().hex[:6]}",
            agent_type="behavioral_anomaly",
            event_bus=event_bus,
            shared_memory=shared_memory,
        )
        # Sliding window of recent scores for adaptive thresholding
        self._recent_scores: List[float] = []
        self._baseline_means: Dict[str, float] = {
            "failed_logins": 1.2,
            "bytes_sent": 5000.0,
            "bytes_received": 8000.0,
            "packet_count": 50.0,
            "connection_duration": 30.0,
        }

    async def process(self, event: dict) -> dict:
        """Score a telemetry event for anomalous behaviour."""
        score = 0.0
        feature_contributions: Dict[str, float] = {}

        # --- Feature extraction and deviation scoring ---
        for feat, weight in _FEATURE_WEIGHTS.items():
            raw_val = float(event.get(feat, 0))
            baseline = self._baseline_means.get(feat, 1.0)

            if baseline > 0 and raw_val > 0:
                # Z-score-like deviation: how many multiples above baseline
                deviation = max(0.0, (raw_val - baseline) / max(baseline, 1.0))
                contribution = min(1.0, deviation) * weight
            else:
                contribution = 0.0

            feature_contributions[feat] = round(contribution, 4)
            score += contribution

        # --- Event-type risk boost ---
        event_type = event.get("event_type", "")
        if event_type in _HIGH_RISK_EVENT_TYPES:
            score += 0.25
            feature_contributions["event_type_boost"] = 0.25

        # --- Time-of-day anomaly ---
        try:
            hour = datetime.fromisoformat(str(event.get("timestamp", ""))).hour
        except (ValueError, TypeError):
            hour = datetime.now(timezone.utc).hour
        if hour < 6 or hour > 22:
            score += 0.10
            feature_contributions["off_hours"] = 0.10

        # --- Normalise to [0, 1] ---
        anomaly_score = min(1.0, max(0.0, score))

        # Adaptive threshold from recent history
        self._recent_scores.append(anomaly_score)
        if len(self._recent_scores) > 500:
            self._recent_scores = self._recent_scores[-500:]
        mean_score = sum(self._recent_scores) / len(self._recent_scores)
        adaptive_threshold = min(0.85, mean_score + 0.30)

        is_anomaly = anomaly_score >= adaptive_threshold
        classification = "anomalous" if is_anomaly else "normal"
        severity = self._score_to_severity(anomaly_score)

        # Persist to shared memory
        if self._shared_memory and is_anomaly:
            src_ip = event.get("src_ip", "unknown")
            key = f"anomaly:{src_ip}:{int(time.time())}"
            self._shared_memory.set(key, {
                "score": anomaly_score, "severity": severity,
                "event_type": event_type,
            })

        log.info(
            "BehavioralAnomalyAgent scored event",
            anomaly_score=round(anomaly_score, 4),
            classification=classification,
            severity=severity,
            event_type=event_type,
        )

        return {
            "anomaly_score": round(anomaly_score, 4),
            "classification": classification,
            "is_anomaly": is_anomaly,
            "severity": severity,
            "adaptive_threshold": round(adaptive_threshold, 4),
            "feature_contributions": feature_contributions,
            "event_type": event_type,
            "src_ip": event.get("src_ip", "unknown"),
            "dst_ip": event.get("dst_ip", "unknown"),
        }

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 0.85:
            return "CRITICAL"
        if score >= 0.65:
            return "HIGH"
        if score >= 0.40:
            return "MEDIUM"
        if score >= 0.20:
            return "LOW"
        return "INFO"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Agent 2 — Threat Attribution Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Offline APT indicator database — maps IOC patterns to APT groups
_APT_INDICATORS: Dict[str, Dict[str, Any]] = {
    "APT28": {
        "name": "Fancy Bear",
        "nation_state": "Russia",
        "techniques": {"T1566", "T1059", "T1071", "T1078", "T1053"},
        "ioc_patterns": {"powershell", "mimikatz", "cobaltstrike", "svchost"},
        "event_types": {"Brute_Force_Login", "PowerShell_Execution", "Credential_Dump"},
        "target_sectors": ["government", "military", "energy"],
    },
    "APT29": {
        "name": "Cozy Bear",
        "nation_state": "Russia",
        "techniques": {"T1195", "T1059", "T1071", "T1003", "T1055"},
        "ioc_patterns": {"sunburst", "wellmess", "wmic", "rundll32"},
        "event_types": {"Data_Exfiltration", "DNS_Tunneling", "Suspicious_Process_Spawn"},
        "target_sectors": ["government", "healthcare", "technology"],
    },
    "APT41": {
        "name": "Double Dragon",
        "nation_state": "China",
        "techniques": {"T1190", "T1059", "T1021", "T1210", "T1486"},
        "ioc_patterns": {"shadowpad", "winnti", "gh0st", "plugx"},
        "event_types": {"Port_Scan", "Ransomware_Encryption", "Data_Exfiltration"},
        "target_sectors": ["finance", "telecom", "gaming"],
    },
    "Lazarus": {
        "name": "Lazarus Group",
        "nation_state": "North Korea",
        "techniques": {"T1566", "T1486", "T1059", "T1105", "T1571"},
        "ioc_patterns": {"wannacry", "fastcash", "applejeus", "lazarus"},
        "event_types": {"Ransomware_Encryption", "Data_Exfiltration", "PowerShell_Execution"},
        "target_sectors": ["finance", "cryptocurrency", "defense"],
    },
    "FIN7": {
        "name": "Carbanak Group",
        "nation_state": "Unknown",
        "techniques": {"T1566", "T1059", "T1055", "T1041", "T1053"},
        "ioc_patterns": {"carbanak", "griffon", "bateleur", "boostwrite"},
        "event_types": {"Brute_Force_Login", "Data_Exfiltration", "PowerShell_Execution"},
        "target_sectors": ["hospitality", "retail", "finance"],
    },
}


class ThreatAttributionAgent(BaseAgent):
    """
    Correlates detected anomaly IOCs with known APT group indicators.

    Input : anomaly event dict (from BehavioralAnomalyAgent).
    Output: APT attribution with confidence scores per candidate group.
    """

    def __init__(
        self,
        event_bus: Optional[AgentEventBus] = None,
        shared_memory: Optional[SharedMemory] = None,
    ) -> None:
        super().__init__(
            agent_id=f"attribution-{uuid.uuid4().hex[:6]}",
            agent_type="threat_attribution",
            event_bus=event_bus,
            shared_memory=shared_memory,
        )

    async def process(self, event: dict) -> dict:
        """Attribute an anomaly event to known APT groups."""
        event_type = event.get("event_type", "")
        src_ip = event.get("src_ip", "")
        process_name = str(event.get("process_name", "")).lower()
        command_line = str(event.get("command_line", "")).lower()
        anomaly_score = float(event.get("anomaly_score", 0.0))

        candidates: List[Dict[str, Any]] = []

        for apt_id, apt_data in _APT_INDICATORS.items():
            confidence = 0.0

            # Match on event type
            if event_type in apt_data["event_types"]:
                confidence += 0.35

            # Match on IOC patterns in process name or command line
            search_text = f"{process_name} {command_line}"
            pattern_matches = sum(
                1 for p in apt_data["ioc_patterns"] if p in search_text
            )
            if pattern_matches > 0:
                confidence += min(0.40, pattern_matches * 0.20)

            # Boost if anomaly score is high (correlated severity)
            if anomaly_score >= 0.7:
                confidence += 0.15
            elif anomaly_score >= 0.4:
                confidence += 0.08

            # Only report if confidence exceeds minimum threshold
            if confidence >= 0.10:
                candidates.append({
                    "apt_group": apt_id,
                    "apt_name": apt_data["name"],
                    "nation_state": apt_data["nation_state"],
                    "confidence": round(min(1.0, confidence), 4),
                    "matched_techniques": sorted(apt_data["techniques"]),
                    "target_sectors": apt_data["target_sectors"],
                })

        # Sort by confidence descending
        candidates.sort(key=lambda c: c["confidence"], reverse=True)

        primary = candidates[0] if candidates else None
        attribution = primary["apt_group"] if primary else "unknown"
        overall_confidence = primary["confidence"] if primary else 0.0

        # Persist best match
        if self._shared_memory and primary:
            self._shared_memory.set(f"attribution:{src_ip}", {
                "apt_group": attribution,
                "confidence": overall_confidence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        log.info(
            "ThreatAttributionAgent completed",
            attribution=attribution,
            confidence=overall_confidence,
            candidates=len(candidates),
        )

        return {
            "primary_attribution": attribution,
            "primary_confidence": overall_confidence,
            "primary_detail": primary,
            "all_candidates": candidates[:5],
            "event_type": event_type,
            "src_ip": src_ip,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Agent 3 — MITRE Mapping Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Reuse STAGE_MITRE mapping from core.playbook_engine
_STAGE_MITRE: Dict[str, Tuple[str, str, str]] = {
    "Reconnaissance":       ("T1595", "Active Scanning", "Reconnaissance"),
    "Credential_Access":    ("T1110", "Brute Force", "Credential Access"),
    "Lateral_Movement":     ("T1021", "Remote Services", "Lateral Movement"),
    "Execution":            ("T1059", "Command and Scripting Interpreter", "Execution"),
    "Persistence":          ("T1053", "Scheduled Task/Job", "Persistence"),
    "Privilege_Escalation": ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "Exfiltration":         ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "Defense_Evasion":      ("T1036", "Masquerading", "Defense Evasion"),
    "Collection":           ("T1005", "Data from Local System", "Collection"),
    "Impact":               ("T1486", "Data Encrypted for Impact", "Impact"),
    "Command_Control":      ("T1071", "Application Layer Protocol", "Command and Control"),
    "Discovery":            ("T1082", "System Information Discovery", "Discovery"),
    "Initial_Access":       ("T1566", "Phishing", "Initial Access"),
    "Resource_Development": ("T1583", "Acquire Infrastructure", "Resource Development"),
}

# Event-type to attack-stage mapping
_EVENT_TO_STAGE: Dict[str, str] = {
    "Port_Scan":                "Reconnaissance",
    "Network_Sweep":            "Reconnaissance",
    "DNS_Query":                "Reconnaissance",
    "Brute_Force_Login":        "Credential_Access",
    "Password_Spray":           "Credential_Access",
    "Credential_Dump":          "Credential_Access",
    "Normal_Connection":        "Lateral_Movement",
    "HTTP_Request":             "Lateral_Movement",
    "PowerShell_Execution":     "Execution",
    "Suspicious_Process_Spawn": "Execution",
    "Process_Start":            "Execution",
    "Registry_Modification":    "Persistence",
    "Scheduled_Task":           "Persistence",
    "File_Access":              "Privilege_Escalation",
    "Data_Exfiltration":        "Exfiltration",
    "DNS_Tunneling":            "Exfiltration",
    "Ransomware_Encryption":    "Impact",
    "Authentication_Success":   "Credential_Access",
}


class MitreMappingAgent(BaseAgent):
    """
    Maps security events to the MITRE ATT&CK Enterprise framework.

    Input : security event dict with ``event_type``, ``process_name``, etc.
    Output: list of tactic / technique mappings with confidence scores.
    """

    def __init__(
        self,
        event_bus: Optional[AgentEventBus] = None,
        shared_memory: Optional[SharedMemory] = None,
    ) -> None:
        super().__init__(
            agent_id=f"mitre-{uuid.uuid4().hex[:6]}",
            agent_type="mitre_mapping",
            event_bus=event_bus,
            shared_memory=shared_memory,
        )

    async def process(self, event: dict) -> dict:
        """Map event to MITRE ATT&CK techniques."""
        event_type = event.get("event_type", "")
        process_name = str(event.get("process_name", "")).lower()
        command_line = str(event.get("command_line", "")).lower()

        mappings: List[Dict[str, Any]] = []
        matched_stages: Set[str] = set()

        # --- Primary mapping via event type ---
        stage = _EVENT_TO_STAGE.get(event_type)
        if stage and stage in _STAGE_MITRE:
            matched_stages.add(stage)
            tech_id, tech_name, tactic = _STAGE_MITRE[stage]
            mappings.append({
                "technique_id": tech_id,
                "technique_name": tech_name,
                "tactic": tactic,
                "confidence": 0.85,
                "match_source": "event_type",
            })

        # --- Secondary mapping via command-line heuristics ---
        cli_patterns: Dict[str, str] = {
            "powershell": "Execution",
            "cmd.exe": "Execution",
            "wmic": "Execution",
            "schtasks": "Persistence",
            "reg add": "Persistence",
            "net user": "Discovery",
            "net group": "Discovery",
            "mimikatz": "Credential_Access",
            "sekurlsa": "Credential_Access",
            "certutil": "Defense_Evasion",
            "rundll32": "Defense_Evasion",
            "bitsadmin": "Defense_Evasion",
            "psexec": "Lateral_Movement",
            "wmiexec": "Lateral_Movement",
            "curl": "Command_Control",
            "wget": "Command_Control",
            "ssh": "Lateral_Movement",
            "rdp": "Lateral_Movement",
            "rar": "Collection",
            "7z": "Collection",
            "base64": "Defense_Evasion",
        }

        for pattern, cli_stage in cli_patterns.items():
            if pattern in command_line or pattern in process_name:
                if cli_stage not in matched_stages and cli_stage in _STAGE_MITRE:
                    matched_stages.add(cli_stage)
                    tech_id, tech_name, tactic = _STAGE_MITRE[cli_stage]
                    mappings.append({
                        "technique_id": tech_id,
                        "technique_name": tech_name,
                        "tactic": tactic,
                        "confidence": 0.65,
                        "match_source": f"cli_pattern:{pattern}",
                    })

        # --- Incorporate attribution techniques if available ---
        attribution_techniques = event.get("matched_techniques", [])
        for tech_id in attribution_techniques:
            if not any(m["technique_id"] == tech_id for m in mappings):
                # Lookup technique name from our database
                tech_name = self._lookup_technique(tech_id)
                mappings.append({
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic": "attributed",
                    "confidence": 0.55,
                    "match_source": "apt_attribution",
                })

        # Sort by confidence
        mappings.sort(key=lambda m: m["confidence"], reverse=True)

        # Determine kill-chain position
        kill_chain_order = [
            "Reconnaissance", "Resource_Development", "Initial_Access",
            "Execution", "Persistence", "Privilege_Escalation",
            "Defense_Evasion", "Credential_Access", "Discovery",
            "Lateral_Movement", "Collection", "Command_Control",
            "Exfiltration", "Impact",
        ]
        current_position = 0
        for idx, stage_name in enumerate(kill_chain_order):
            if stage_name in matched_stages:
                current_position = max(current_position, idx)
        kill_chain_progress = round(current_position / max(len(kill_chain_order) - 1, 1), 4)

        # Persist
        if self._shared_memory:
            src_ip = event.get("src_ip", "unknown")
            self._shared_memory.set(f"mitre:{src_ip}", {
                "mappings": mappings[:5],
                "kill_chain_progress": kill_chain_progress,
            })

        log.info(
            "MitreMappingAgent completed",
            techniques_mapped=len(mappings),
            kill_chain_progress=kill_chain_progress,
        )

        return {
            "mitre_mappings": mappings[:10],
            "matched_stages": sorted(matched_stages),
            "kill_chain_progress": kill_chain_progress,
            "primary_tactic": mappings[0]["tactic"] if mappings else "unknown",
            "primary_technique": mappings[0]["technique_id"] if mappings else "unknown",
        }

    @staticmethod
    def _lookup_technique(tech_id: str) -> str:
        """Offline lookup of technique name by ID."""
        _TECHNIQUE_NAMES: Dict[str, str] = {
            "T1566": "Phishing", "T1059": "Command and Scripting Interpreter",
            "T1071": "Application Layer Protocol", "T1078": "Valid Accounts",
            "T1053": "Scheduled Task/Job", "T1195": "Supply Chain Compromise",
            "T1003": "OS Credential Dumping", "T1055": "Process Injection",
            "T1190": "Exploit Public-Facing Application", "T1021": "Remote Services",
            "T1210": "Exploitation of Remote Services", "T1486": "Data Encrypted for Impact",
            "T1105": "Ingress Tool Transfer", "T1571": "Non-Standard Port",
            "T1041": "Exfiltration Over C2 Channel", "T1110": "Brute Force",
            "T1595": "Active Scanning", "T1548": "Abuse Elevation Control",
            "T1036": "Masquerading", "T1082": "System Information Discovery",
        }
        return _TECHNIQUE_NAMES.get(tech_id, f"Technique {tech_id}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Agent 4 — CVE Prioritization Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Offline CVE database with CVSS, exploit availability, and asset-class relevance
_CVE_DATABASE: Dict[str, Dict[str, Any]] = {
    "CVE-2024-21887": {
        "description": "Ivanti Connect Secure command injection",
        "cvss_base": 9.1, "exploited_in_wild": True,
        "affected_products": ["vpn", "gateway"],
        "cwe": "CWE-77",
    },
    "CVE-2023-44228": {
        "description": "Apache Log4j remote code execution",
        "cvss_base": 10.0, "exploited_in_wild": True,
        "affected_products": ["java", "web_server", "application_server"],
        "cwe": "CWE-502",
    },
    "CVE-2024-3400": {
        "description": "Palo Alto PAN-OS GlobalProtect command injection",
        "cvss_base": 10.0, "exploited_in_wild": True,
        "affected_products": ["firewall", "vpn"],
        "cwe": "CWE-77",
    },
    "CVE-2023-36884": {
        "description": "Microsoft Office HTML RCE",
        "cvss_base": 8.8, "exploited_in_wild": True,
        "affected_products": ["office", "windows"],
        "cwe": "CWE-416",
    },
    "CVE-2024-1709": {
        "description": "ConnectWise ScreenConnect authentication bypass",
        "cvss_base": 10.0, "exploited_in_wild": True,
        "affected_products": ["remote_management"],
        "cwe": "CWE-288",
    },
    "CVE-2023-27997": {
        "description": "Fortinet FortiGate SSL-VPN heap overflow",
        "cvss_base": 9.8, "exploited_in_wild": True,
        "affected_products": ["firewall", "vpn"],
        "cwe": "CWE-122",
    },
    "CVE-2024-0012": {
        "description": "PAN-OS management interface authentication bypass",
        "cvss_base": 9.8, "exploited_in_wild": True,
        "affected_products": ["firewall"],
        "cwe": "CWE-306",
    },
    "CVE-2023-46805": {
        "description": "Ivanti Connect Secure authentication bypass",
        "cvss_base": 8.2, "exploited_in_wild": True,
        "affected_products": ["vpn", "gateway"],
        "cwe": "CWE-287",
    },
}


class CVEPrioritizationAgent(BaseAgent):
    """
    Evaluates asset vulnerability exposure and prioritises CVEs by
    contextual risk, weighing CVSS, exploit availability, asset criticality,
    and relevance to detected attack techniques.

    Input : asset info dict with ``asset_type``, ``criticality``,
            ``services``, ``os_type``, and optionally ``matched_techniques``.
    Output: prioritised list of CVE risk entries.
    """

    def __init__(
        self,
        event_bus: Optional[AgentEventBus] = None,
        shared_memory: Optional[SharedMemory] = None,
    ) -> None:
        super().__init__(
            agent_id=f"cve-{uuid.uuid4().hex[:6]}",
            agent_type="cve_prioritization",
            event_bus=event_bus,
            shared_memory=shared_memory,
        )

    async def process(self, event: dict) -> dict:
        """Evaluate and rank CVEs for the given asset context."""
        asset_type = str(event.get("asset_type", "server")).lower()
        criticality = str(event.get("criticality", "MEDIUM")).upper()
        services = [s.lower() for s in event.get("services", [])]
        os_type = str(event.get("os_type", "linux")).lower()
        matched_techniques = event.get("matched_techniques", [])

        # Criticality weight
        crit_weights = {"LOW": 0.5, "MEDIUM": 0.75, "HIGH": 1.0, "CRITICAL": 1.25}
        crit_multiplier = crit_weights.get(criticality, 0.75)

        prioritised: List[Dict[str, Any]] = []

        for cve_id, cve_data in _CVE_DATABASE.items():
            # Base score from CVSS
            base_score = cve_data["cvss_base"] / 10.0

            # Exploit availability boost
            exploit_boost = 0.15 if cve_data["exploited_in_wild"] else 0.0

            # Product relevance — does this CVE affect services running on the asset?
            relevance = 0.0
            affected = cve_data["affected_products"]
            for product in affected:
                if product in services or product in asset_type or product in os_type:
                    relevance += 0.20
            relevance = min(0.40, relevance)

            # Technique correlation — if active attack uses techniques related to this CVE
            technique_boost = 0.0
            if matched_techniques:
                # CVEs exploited via initial access / execution are highly relevant
                technique_boost = 0.10

            # Composite risk score
            risk_score = (base_score * 0.45 + exploit_boost + relevance + technique_boost) * crit_multiplier
            risk_score = round(min(1.0, risk_score), 4)

            priority = "CRITICAL" if risk_score >= 0.80 else (
                "HIGH" if risk_score >= 0.60 else (
                    "MEDIUM" if risk_score >= 0.35 else "LOW"
                )
            )

            prioritised.append({
                "cve_id": cve_id,
                "description": cve_data["description"],
                "cvss_base": cve_data["cvss_base"],
                "risk_score": risk_score,
                "priority": priority,
                "exploited_in_wild": cve_data["exploited_in_wild"],
                "relevance_to_asset": round(relevance, 4),
                "cwe": cve_data["cwe"],
            })

        # Sort by risk score descending
        prioritised.sort(key=lambda c: c["risk_score"], reverse=True)

        total_risk = sum(c["risk_score"] for c in prioritised) / max(len(prioritised), 1)

        log.info(
            "CVEPrioritizationAgent completed",
            cves_evaluated=len(prioritised),
            critical_count=sum(1 for c in prioritised if c["priority"] == "CRITICAL"),
            avg_risk=round(total_risk, 4),
        )

        return {
            "prioritised_cves": prioritised[:10],
            "total_cves_evaluated": len(prioritised),
            "aggregate_risk": round(total_risk, 4),
            "critical_cves": [c for c in prioritised if c["priority"] == "CRITICAL"],
            "asset_context": {
                "asset_type": asset_type,
                "criticality": criticality,
                "services": services,
            },
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Agent 5 — Attack Path Prediction Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class AttackPathPredictionAgent(BaseAgent):
    """
    Predicts probable attack paths from a compromised node using
    graph-based shortest-path and BFS analysis.

    Input : compromised node info (``node_id``, ``src_ip``).
    Output: predicted paths to high-value assets with risk scores.
    """

    def __init__(
        self,
        event_bus: Optional[AgentEventBus] = None,
        shared_memory: Optional[SharedMemory] = None,
    ) -> None:
        super().__init__(
            agent_id=f"attackpath-{uuid.uuid4().hex[:6]}",
            agent_type="attack_path_prediction",
            event_bus=event_bus,
            shared_memory=shared_memory,
        )
        # Internal network graph built from events
        self._network: nx.DiGraph = nx.DiGraph()
        self._bootstrap_network()

    def _bootstrap_network(self) -> None:
        """Seed with a representative enterprise network topology."""
        hosts = [
            ("workstation-01", {"type": "workstation", "criticality": "LOW", "os": "Windows 11"}),
            ("workstation-02", {"type": "workstation", "criticality": "LOW", "os": "Windows 10"}),
            ("jump-server", {"type": "server", "criticality": "MEDIUM", "os": "Linux"}),
            ("file-server", {"type": "server", "criticality": "HIGH", "os": "Linux"}),
            ("db-server", {"type": "database", "criticality": "CRITICAL", "os": "Linux"}),
            ("dc-01", {"type": "domain_controller", "criticality": "CRITICAL", "os": "Windows Server"}),
            ("web-server", {"type": "server", "criticality": "MEDIUM", "os": "Linux"}),
            ("mail-server", {"type": "server", "criticality": "HIGH", "os": "Linux"}),
        ]
        for node_id, attrs in hosts:
            self._network.add_node(node_id, **attrs)

        edges = [
            ("workstation-01", "jump-server", 0.75),
            ("workstation-02", "jump-server", 0.70),
            ("jump-server", "file-server", 0.60),
            ("jump-server", "db-server", 0.45),
            ("jump-server", "dc-01", 0.35),
            ("file-server", "db-server", 0.55),
            ("file-server", "dc-01", 0.40),
            ("web-server", "db-server", 0.50),
            ("web-server", "file-server", 0.45),
            ("mail-server", "dc-01", 0.30),
            ("workstation-01", "mail-server", 0.65),
        ]
        for src, dst, prob in edges:
            self._network.add_edge(src, dst, lateral_probability=prob)

    async def process(self, event: dict) -> dict:
        """Predict attack paths from a compromised node."""
        src_ip = event.get("src_ip", "")
        node_id = event.get("node_id", "")

        # Resolve starting node: use node_id if exists, else find closest match
        start_node = None
        if node_id and node_id in self._network:
            start_node = node_id
        elif src_ip:
            # Check if src_ip was dynamically added
            if src_ip not in self._network:
                self._network.add_node(src_ip, type="unknown", criticality="MEDIUM")
                # Connect to closest workstation
                for ws in ["workstation-01", "workstation-02"]:
                    if ws in self._network:
                        self._network.add_edge(src_ip, ws, lateral_probability=0.5)
                        break
            start_node = src_ip

        if not start_node or start_node not in self._network:
            start_node = "workstation-01"

        # Identify crown jewels (CRITICAL / HIGH criticality)
        crown_jewels = [
            n for n, d in self._network.nodes(data=True)
            if d.get("criticality") in ("CRITICAL", "HIGH") and n != start_node
        ]

        predicted_paths: List[Dict[str, Any]] = []

        for target in crown_jewels:
            try:
                paths = list(nx.all_simple_paths(
                    self._network, start_node, target, cutoff=5,
                ))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                paths = []

            for path in paths[:3]:  # Top 3 paths per target
                # Calculate cumulative path risk
                path_risk = 1.0
                for i in range(len(path) - 1):
                    edge_data = self._network.edges.get((path[i], path[i + 1]), {})
                    step_prob = edge_data.get("lateral_probability", 0.1)
                    path_risk *= step_prob

                target_data = self._network.nodes.get(target, {})
                predicted_paths.append({
                    "path": path,
                    "target": target,
                    "target_type": target_data.get("type", "unknown"),
                    "target_criticality": target_data.get("criticality", "MEDIUM"),
                    "hop_count": len(path) - 1,
                    "cumulative_probability": round(path_risk, 6),
                    "risk_score": round(min(1.0, (1.0 - path_risk) + 0.1 * len(path)), 4),
                })

        # Sort by risk score descending
        predicted_paths.sort(key=lambda p: p["risk_score"], reverse=True)

        # Determine most likely next hop
        next_hops = []
        for neighbor in self._network.neighbors(start_node):
            edge_data = self._network.edges[start_node, neighbor]
            next_hops.append({
                "node": neighbor,
                "probability": edge_data.get("lateral_probability", 0.1),
            })
        next_hops.sort(key=lambda h: h["probability"], reverse=True)

        log.info(
            "AttackPathPredictionAgent completed",
            start_node=start_node,
            paths_found=len(predicted_paths),
            crown_jewels=len(crown_jewels),
        )

        return {
            "start_node": start_node,
            "predicted_paths": predicted_paths[:10],
            "most_likely_next_hops": next_hops[:5],
            "crown_jewels_at_risk": crown_jewels,
            "total_paths_analyzed": len(predicted_paths),
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Agent 6 — Digital Twin Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class DigitalTwinAgent(BaseAgent):
    """
    Runs threat simulations on a digital twin of the enterprise network.

    Uses the same ``networkx``-based topology as the real
    ``DigitalTwinEngine`` to forecast ransomware blast radius,
    lateral-movement propagation speed, and asset impact.

    Input : threat scenario dict with ``scenario_type``, ``start_node``, etc.
    Output: simulation results including blast radius, impacted hosts,
            crown-jewel exposure.
    """

    def __init__(
        self,
        event_bus: Optional[AgentEventBus] = None,
        shared_memory: Optional[SharedMemory] = None,
    ) -> None:
        super().__init__(
            agent_id=f"twin-{uuid.uuid4().hex[:6]}",
            agent_type="digital_twin",
            event_bus=event_bus,
            shared_memory=shared_memory,
        )
        self._twin: nx.DiGraph = nx.DiGraph()
        self._bootstrap_twin()

    def _bootstrap_twin(self) -> None:
        """Build the digital-twin network topology."""
        nodes = [
            ("HOST-01", {"type": "workstation", "criticality": "LOW", "os": "Windows 11", "subnet": "10.1.1.0/24"}),
            ("HOST-02", {"type": "workstation", "criticality": "MEDIUM", "os": "Windows 10", "subnet": "10.1.1.0/24"}),
            ("FILESERVER-01", {"type": "fileserver", "criticality": "HIGH", "os": "Linux", "subnet": "10.1.2.0/24"}),
            ("DB-01", {"type": "database", "criticality": "CRITICAL", "os": "RedHat", "subnet": "10.1.3.0/24"}),
            ("DC-01", {"type": "domain_controller", "criticality": "CRITICAL", "os": "Windows Server 2022", "subnet": "10.1.3.0/24"}),
            ("WEB-01", {"type": "webserver", "criticality": "MEDIUM", "os": "Linux", "subnet": "10.1.4.0/24"}),
            ("MAIL-01", {"type": "mailserver", "criticality": "HIGH", "os": "Linux", "subnet": "10.1.2.0/24"}),
            ("SCADA-01", {"type": "scada_hmi", "criticality": "CRITICAL", "os": "Windows", "subnet": "10.2.0.0/24"}),
        ]
        for nid, attrs in nodes:
            self._twin.add_node(nid, **attrs)

        edges = [
            ("HOST-01", "FILESERVER-01", {"protocol": "SMB", "infection_prob": 0.55}),
            ("HOST-02", "FILESERVER-01", {"protocol": "SMB", "infection_prob": 0.50}),
            ("FILESERVER-01", "DB-01", {"protocol": "TCP", "infection_prob": 0.35}),
            ("FILESERVER-01", "DC-01", {"protocol": "Kerberos", "infection_prob": 0.30}),
            ("HOST-02", "DC-01", {"protocol": "RDP", "infection_prob": 0.40}),
            ("WEB-01", "DB-01", {"protocol": "TCP", "infection_prob": 0.45}),
            ("WEB-01", "FILESERVER-01", {"protocol": "HTTP", "infection_prob": 0.35}),
            ("MAIL-01", "DC-01", {"protocol": "LDAP", "infection_prob": 0.25}),
            ("HOST-01", "MAIL-01", {"protocol": "SMTP", "infection_prob": 0.40}),
        ]
        for src, dst, attrs in edges:
            self._twin.add_edge(src, dst, **attrs)

    async def process(self, event: dict) -> dict:
        """Run a threat simulation on the digital twin."""
        scenario = event.get("scenario_type", "ransomware_spread")
        start_node = event.get("start_node", "HOST-01")
        infection_prob = float(event.get("infection_probability", 0.45))

        if start_node not in self._twin:
            # Map IP to nearest known host
            start_node = "HOST-01"

        if scenario == "ransomware_spread":
            result = self._simulate_ransomware(start_node, infection_prob)
        elif scenario == "lateral_movement":
            result = self._simulate_lateral(start_node)
        elif scenario == "data_exfiltration":
            result = self._simulate_exfiltration(start_node)
        else:
            result = self._simulate_ransomware(start_node, infection_prob)

        log.info(
            "DigitalTwinAgent simulation completed",
            scenario=scenario, start_node=start_node,
            blast_radius=result.get("blast_radius_score", 0),
        )

        return result

    def _simulate_ransomware(self, start: str, base_prob: float) -> dict:
        """BFS-based ransomware propagation simulation."""
        visited: Dict[str, float] = {start: 1.0}
        queue: List[Tuple[str, float, int]] = [(start, 1.0, 0)]
        infection_timeline: List[Dict[str, Any]] = []
        critical_impacted: List[str] = []

        while queue:
            curr, prob, step = queue.pop(0)
            if prob < 0.05:
                continue

            node_data = self._twin.nodes.get(curr, {})
            infection_timeline.append({
                "node": curr, "step": step,
                "infection_probability": round(prob, 4),
                "type": node_data.get("type", "unknown"),
                "criticality": node_data.get("criticality", "MEDIUM"),
            })

            if node_data.get("criticality") in ("CRITICAL", "HIGH"):
                critical_impacted.append(curr)

            for neighbor in self._twin.neighbors(curr):
                if neighbor not in visited:
                    edge_data = self._twin.edges[curr, neighbor]
                    step_prob = edge_data.get("infection_prob", base_prob)
                    next_prob = prob * step_prob
                    visited[neighbor] = next_prob
                    queue.append((neighbor, next_prob, step + 1))

        total_nodes = self._twin.number_of_nodes()
        blast_score = round(len(visited) / max(total_nodes, 1), 4)

        # Estimate containment time (hours)
        containment_hours = round(len(visited) * 2.5 + len(critical_impacted) * 8.0, 1)

        return {
            "scenario": "ransomware_spread",
            "start_node": start,
            "blast_radius_score": blast_score,
            "hosts_impacted": len(visited),
            "critical_assets_impacted": len(set(critical_impacted)),
            "critical_asset_names": sorted(set(critical_impacted)),
            "infection_timeline": infection_timeline,
            "estimated_containment_hours": containment_hours,
            "subnets_affected": sorted(set(
                self._twin.nodes[n].get("subnet", "unknown") for n in visited
            )),
        }

    def _simulate_lateral(self, start: str) -> dict:
        """Simulate lateral movement from a compromised node."""
        paths_to_crown_jewels: List[Dict[str, Any]] = []
        crown_jewels = [
            n for n, d in self._twin.nodes(data=True)
            if d.get("criticality") == "CRITICAL"
        ]

        for cj in crown_jewels:
            if cj == start:
                continue
            try:
                path = nx.shortest_path(self._twin, start, cj)
                risk = 1.0
                for i in range(len(path) - 1):
                    edge = self._twin.edges.get((path[i], path[i + 1]), {})
                    risk *= edge.get("infection_prob", 0.3)
                paths_to_crown_jewels.append({
                    "target": cj, "path": path,
                    "hops": len(path) - 1,
                    "success_probability": round(risk, 6),
                })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        paths_to_crown_jewels.sort(key=lambda p: p["success_probability"], reverse=True)

        return {
            "scenario": "lateral_movement",
            "start_node": start,
            "crown_jewels_reachable": len(paths_to_crown_jewels),
            "paths": paths_to_crown_jewels,
            "highest_risk_target": paths_to_crown_jewels[0]["target"] if paths_to_crown_jewels else None,
        }

    def _simulate_exfiltration(self, start: str) -> dict:
        """Estimate data exfiltration risk from a node."""
        reachable = set(nx.descendants(self._twin, start)) if start in self._twin else set()
        data_stores = [
            n for n in reachable
            if self._twin.nodes[n].get("type") in ("database", "fileserver")
        ]
        data_volume_gb = len(data_stores) * 500  # estimated GB per data store

        return {
            "scenario": "data_exfiltration",
            "start_node": start,
            "reachable_nodes": len(reachable),
            "data_stores_accessible": len(data_stores),
            "data_store_names": data_stores,
            "estimated_data_exposure_gb": data_volume_gb,
            "exfiltration_risk": round(min(1.0, len(data_stores) * 0.35), 4),
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Agent 7 — SOAR Response Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Response playbook templates by severity
_RESPONSE_PLAYBOOKS: Dict[str, List[Dict[str, Any]]] = {
    "CRITICAL": [
        {"action": "isolate_host", "description": "Network-isolate compromised endpoint", "timeout_s": 30},
        {"action": "block_ip", "description": "Add attacker IP to perimeter firewall deny list", "timeout_s": 15},
        {"action": "disable_account", "description": "Disable compromised user account in Active Directory", "timeout_s": 20},
        {"action": "snapshot_forensics", "description": "Create forensic VM snapshot before remediation", "timeout_s": 60},
        {"action": "revoke_tokens", "description": "Revoke all active OAuth/SSO tokens for affected user", "timeout_s": 15},
        {"action": "notify_soc", "description": "Page on-call SOC analyst via PagerDuty", "timeout_s": 10},
    ],
    "HIGH": [
        {"action": "block_ip", "description": "Block attacker IP at firewall", "timeout_s": 15},
        {"action": "disable_account", "description": "Disable affected user account", "timeout_s": 20},
        {"action": "collect_evidence", "description": "Gather process trees and network logs", "timeout_s": 45},
        {"action": "notify_soc", "description": "Create SOC ticket with HIGH priority", "timeout_s": 10},
    ],
    "MEDIUM": [
        {"action": "monitor_enhanced", "description": "Enable enhanced monitoring for source IP", "timeout_s": 10},
        {"action": "collect_evidence", "description": "Collect relevant log artifacts", "timeout_s": 30},
        {"action": "notify_soc", "description": "Create SOC ticket with MEDIUM priority", "timeout_s": 10},
    ],
    "LOW": [
        {"action": "log_event", "description": "Log event for future correlation", "timeout_s": 5},
        {"action": "update_watchlist", "description": "Add source IP to watchlist", "timeout_s": 5},
    ],
}


class SOARResponseAgent(BaseAgent):
    """
    Executes automated response playbooks based on threat severity.

    Input : threat alert dict with ``severity``, ``src_ip``,
            ``dst_ip``, ``event_type``.
    Output: execution results with action statuses and audit trail.
    """

    def __init__(
        self,
        event_bus: Optional[AgentEventBus] = None,
        shared_memory: Optional[SharedMemory] = None,
    ) -> None:
        super().__init__(
            agent_id=f"soar-{uuid.uuid4().hex[:6]}",
            agent_type="soar_response",
            event_bus=event_bus,
            shared_memory=shared_memory,
        )
        self._execution_log: List[Dict[str, Any]] = []

    async def process(self, event: dict) -> dict:
        """Execute response playbook for a threat alert."""
        severity = event.get("severity", "MEDIUM").upper()
        src_ip = event.get("src_ip", "0.0.0.0")
        dst_ip = event.get("dst_ip", "0.0.0.0")
        event_type = event.get("event_type", "unknown")
        user_id = event.get("user_id", "unknown")

        playbook = _RESPONSE_PLAYBOOKS.get(severity, _RESPONSE_PLAYBOOKS["LOW"])
        execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"

        action_results: List[Dict[str, Any]] = []
        all_succeeded = True

        for action_def in playbook:
            action_name = action_def["action"]
            t0 = time.perf_counter()

            # Execute action (simulated but with realistic logging)
            success, detail = await self._execute_action(
                action_name, src_ip=src_ip, dst_ip=dst_ip,
                user_id=user_id, event_type=event_type,
            )
            elapsed = round((time.perf_counter() - t0) * 1000, 2)

            result = {
                "action": action_name,
                "description": action_def["description"],
                "status": "completed" if success else "failed",
                "execution_time_ms": elapsed,
                "detail": detail,
            }
            action_results.append(result)

            if not success:
                all_succeeded = False
                log.warning(
                    "SOAR action failed", action=action_name,
                    execution_id=execution_id, detail=detail,
                )

        # Audit trail
        execution_record = {
            "execution_id": execution_id,
            "severity": severity,
            "src_ip": src_ip,
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actions": action_results,
            "all_succeeded": all_succeeded,
        }
        self._execution_log.append(execution_record)

        if self._shared_memory:
            self._shared_memory.set(f"soar_exec:{execution_id}", execution_record)

        log.info(
            "SOARResponseAgent playbook executed",
            execution_id=execution_id,
            severity=severity,
            actions_total=len(action_results),
            actions_succeeded=sum(1 for a in action_results if a["status"] == "completed"),
        )

        return {
            "execution_id": execution_id,
            "playbook_severity": severity,
            "actions_executed": action_results,
            "all_succeeded": all_succeeded,
            "response_summary": f"Executed {len(action_results)} response actions for {severity} alert from {src_ip}",
        }

    async def _execute_action(
        self, action: str, *, src_ip: str, dst_ip: str,
        user_id: str, event_type: str,
    ) -> Tuple[bool, str]:
        """Simulate execution of a single SOAR action."""
        executors: Dict[str, Callable] = {
            "isolate_host": lambda: (True, f"Host {dst_ip} isolated from network via EDR API"),
            "block_ip": lambda: (True, f"Firewall rule added: DENY {src_ip} → ANY (all ports)"),
            "disable_account": lambda: (True, f"AD account '{user_id}' disabled via LDAP modify"),
            "snapshot_forensics": lambda: (True, f"VM snapshot '{dst_ip}-forensic-{int(time.time())}' created"),
            "revoke_tokens": lambda: (True, f"All OAuth/SAML tokens revoked for '{user_id}'"),
            "notify_soc": lambda: (True, f"SOC alert dispatched for {event_type} from {src_ip}"),
            "collect_evidence": lambda: (True, f"Evidence collection initiated: process trees, netflow, memory dump"),
            "monitor_enhanced": lambda: (True, f"Enhanced monitoring enabled for {src_ip} (24h window)"),
            "log_event": lambda: (True, f"Event logged to SIEM: {event_type} from {src_ip}"),
            "update_watchlist": lambda: (True, f"IP {src_ip} added to threat watchlist"),
        }

        executor = executors.get(action)
        if executor:
            success, detail = executor()
            log.info("SOAR action executed", action=action, detail=detail)
            return success, detail

        return False, f"Unknown action: {action}"

    def get_execution_log(self) -> List[Dict[str, Any]]:
        """Return full audit trail of SOAR executions."""
        return self._execution_log


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Agent 8 — SOC Copilot Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# NL intent classification patterns
_INTENT_PATTERNS: Dict[str, List[str]] = {
    "threat_summary": ["summary", "overview", "status", "situation", "brief"],
    "investigate_ip": ["investigate", "lookup", "whois", "check ip", "trace"],
    "mitre_mapping": ["mitre", "att&ck", "technique", "tactic", "kill chain"],
    "playbook_run": ["respond", "playbook", "contain", "isolate", "block"],
    "risk_assessment": ["risk", "vulnerability", "cve", "exposure", "patch"],
    "attack_path": ["path", "lateral", "movement", "route", "predict"],
    "simulation": ["simulate", "twin", "blast radius", "what if", "scenario"],
    "agent_status": ["agent", "health", "status", "uptime", "agents"],
}


class SOCCopilotAgent(BaseAgent):
    """
    SOC analyst co-pilot: orchestrates other agents, interprets
    natural-language queries, and synthesises structured responses.

    Input : user query string or system alert dict.
    Output: structured response with context, recommendations, and
            cross-references to other agent outputs.
    """

    def __init__(
        self,
        orchestrator: Optional["MultiAgentOrchestrator"] = None,
        event_bus: Optional[AgentEventBus] = None,
        shared_memory: Optional[SharedMemory] = None,
    ) -> None:
        super().__init__(
            agent_id=f"copilot-{uuid.uuid4().hex[:6]}",
            agent_type="soc_copilot",
            event_bus=event_bus,
            shared_memory=shared_memory,
        )
        self._orchestrator = orchestrator
        self._conversation_history: List[Dict[str, str]] = []

    def set_orchestrator(self, orchestrator: "MultiAgentOrchestrator") -> None:
        """Late-bind the orchestrator reference (avoids circular init)."""
        self._orchestrator = orchestrator

    async def process(self, event: dict) -> dict:
        """Process a natural-language query or system alert."""
        query = event.get("query", "")
        alert = event.get("alert", {})

        # Determine intent
        if query:
            intent = self._classify_intent(query)
            response = await self._handle_query(intent, query, event)
        elif alert:
            intent = "alert_triage"
            response = await self._handle_alert(alert)
        else:
            intent = "unknown"
            response = {
                "message": "Please provide a query or alert for analysis.",
                "available_intents": list(_INTENT_PATTERNS.keys()),
            }

        # Track conversation
        self._conversation_history.append({
            "query": query or str(alert)[:200],
            "intent": intent,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        log.info("SOCCopilotAgent processed request", intent=intent)

        return {
            "intent": intent,
            "response": response,
            "conversation_length": len(self._conversation_history),
        }

    def _classify_intent(self, query: str) -> str:
        """Simple keyword-based intent classifier."""
        query_lower = query.lower()
        best_intent = "threat_summary"
        best_score = 0

        for intent, keywords in _INTENT_PATTERNS.items():
            score = sum(1 for kw in keywords if kw in query_lower)
            if score > best_score:
                best_score = score
                best_intent = intent

        return best_intent

    async def _handle_query(self, intent: str, query: str, event: dict) -> dict:
        """Route query to the appropriate handler."""
        handlers = {
            "threat_summary": self._handle_threat_summary,
            "investigate_ip": self._handle_investigate_ip,
            "mitre_mapping": self._handle_mitre_query,
            "playbook_run": self._handle_playbook_run,
            "risk_assessment": self._handle_risk_assessment,
            "attack_path": self._handle_attack_path,
            "simulation": self._handle_simulation,
            "agent_status": self._handle_agent_status,
        }

        handler = handlers.get(intent, self._handle_threat_summary)
        return await handler(query, event)

    async def _handle_threat_summary(self, query: str, event: dict) -> dict:
        """Generate a threat landscape summary."""
        anomaly_keys = self._shared_memory.list_keys("anomaly:") if self._shared_memory else []
        attribution_keys = self._shared_memory.list_keys("attribution:") if self._shared_memory else []

        recent_anomalies = []
        for key in anomaly_keys[-10:]:
            data = self._shared_memory.get(key) if self._shared_memory else None
            if data:
                recent_anomalies.append(data)

        critical_count = sum(1 for a in recent_anomalies if a.get("severity") == "CRITICAL")
        high_count = sum(1 for a in recent_anomalies if a.get("severity") == "HIGH")

        risk_level = "CRITICAL" if critical_count > 0 else (
            "HIGH" if high_count > 0 else "MODERATE"
        )

        return {
            "summary": f"Current threat posture: {risk_level}",
            "total_anomalies_tracked": len(anomaly_keys),
            "active_attributions": len(attribution_keys),
            "critical_alerts": critical_count,
            "high_alerts": high_count,
            "recommendation": (
                "Immediate investigation required — critical alerts detected."
                if critical_count > 0
                else "Continue monitoring — no critical alerts at this time."
            ),
            "recent_anomalies": recent_anomalies[:5],
        }

    async def _handle_investigate_ip(self, query: str, event: dict) -> dict:
        """Investigate a specific IP address."""
        # Extract IP from query
        ip = event.get("src_ip", "")
        if not ip:
            words = query.split()
            for w in words:
                if w.count(".") == 3 and all(p.isdigit() for p in w.split(".")):
                    ip = w
                    break

        if not ip:
            return {"message": "No IP address found in query. Please specify an IP to investigate."}

        # Gather intelligence from shared memory
        anomaly_data = self._shared_memory.get(f"anomaly:{ip}") if self._shared_memory else None
        attribution_data = self._shared_memory.get(f"attribution:{ip}") if self._shared_memory else None
        mitre_data = self._shared_memory.get(f"mitre:{ip}") if self._shared_memory else None

        return {
            "investigated_ip": ip,
            "anomaly_history": anomaly_data or "No anomaly data found",
            "threat_attribution": attribution_data or "No attribution data found",
            "mitre_mapping": mitre_data or "No MITRE mapping found",
            "recommendation": (
                f"IP {ip} has been flagged. Review anomaly and attribution data above."
                if anomaly_data else f"IP {ip} has no recorded threat history."
            ),
        }

    async def _handle_mitre_query(self, query: str, event: dict) -> dict:
        return {
            "message": "MITRE ATT&CK mapping is available via the MitreMappingAgent.",
            "tip": "Submit telemetry events to get real-time technique mappings.",
            "reference": "See mitre_explainer.py for the full offline ATT&CK taxonomy.",
        }

    async def _handle_playbook_run(self, query: str, event: dict) -> dict:
        return {
            "message": "Playbook execution is handled by the SOARResponseAgent.",
            "tip": "Provide a threat alert with severity to trigger automated response.",
        }

    async def _handle_risk_assessment(self, query: str, event: dict) -> dict:
        return {
            "message": "CVE prioritisation is handled by the CVEPrioritizationAgent.",
            "tip": "Provide asset info (type, criticality, services) for a risk assessment.",
        }

    async def _handle_attack_path(self, query: str, event: dict) -> dict:
        return {
            "message": "Attack path prediction is handled by the AttackPathPredictionAgent.",
            "tip": "Provide a compromised node ID or source IP to predict attack paths.",
        }

    async def _handle_simulation(self, query: str, event: dict) -> dict:
        return {
            "message": "Threat simulation is handled by the DigitalTwinAgent.",
            "tip": "Provide scenario_type (ransomware_spread, lateral_movement, data_exfiltration).",
        }

    async def _handle_agent_status(self, query: str, event: dict) -> dict:
        """Report health status of all agents."""
        if self._orchestrator:
            statuses = self._orchestrator.get_agent_status()
            healthy = sum(1 for s in statuses.values() if s.get("healthy"))
            return {
                "total_agents": len(statuses),
                "healthy_agents": healthy,
                "agent_details": statuses,
            }
        return {"message": "Orchestrator not available for status check."}

    async def _handle_alert(self, alert: dict) -> dict:
        """Triage an incoming system alert."""
        severity = alert.get("severity", "MEDIUM")
        event_type = alert.get("event_type", "unknown")

        return {
            "triage_result": f"{severity} alert for {event_type}",
            "recommendation": (
                "Execute CRITICAL response playbook immediately."
                if severity == "CRITICAL"
                else f"Schedule investigation for {severity} {event_type} alert."
            ),
            "alert": alert,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Multi-Agent Orchestrator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Event-type to agent-type routing table
_EVENT_ROUTING: Dict[str, List[str]] = {
    "telemetry":            ["behavioral_anomaly"],
    "anomaly":              ["threat_attribution", "mitre_mapping"],
    "threat_alert":         ["mitre_mapping", "attack_path_prediction", "soar_response"],
    "asset_scan":           ["cve_prioritization"],
    "simulation_request":   ["digital_twin"],
    "query":                ["soc_copilot"],
    "alert":                ["soc_copilot", "soar_response"],
    "investigation":        ["soc_copilot", "threat_attribution"],
}


class MultiAgentOrchestrator:
    """
    Central orchestrator that registers, routes, and manages all
    IMMUNEX agents.

    Provides:
    - Agent lifecycle management (register, health-check, status)
    - Event routing based on event type
    - Full threat-processing pipeline (anomaly → attribution → MITRE →
      path prediction → SOAR response)
    """

    def __init__(self) -> None:
        self._agents: Dict[str, BaseAgent] = {}
        self._agent_type_index: Dict[str, List[str]] = defaultdict(list)
        self.event_bus = AgentEventBus()
        self.shared_memory = SharedMemory()
        self._pipeline_count: int = 0
        self._initialise_agents()
        log.info(
            "MultiAgentOrchestrator initialised",
            agents_registered=len(self._agents),
        )

    def _initialise_agents(self) -> None:
        """Create and register all 8 agent instances."""
        agents: List[BaseAgent] = [
            BehavioralAnomalyAgent(event_bus=self.event_bus, shared_memory=self.shared_memory),
            ThreatAttributionAgent(event_bus=self.event_bus, shared_memory=self.shared_memory),
            MitreMappingAgent(event_bus=self.event_bus, shared_memory=self.shared_memory),
            CVEPrioritizationAgent(event_bus=self.event_bus, shared_memory=self.shared_memory),
            AttackPathPredictionAgent(event_bus=self.event_bus, shared_memory=self.shared_memory),
            DigitalTwinAgent(event_bus=self.event_bus, shared_memory=self.shared_memory),
            SOARResponseAgent(event_bus=self.event_bus, shared_memory=self.shared_memory),
            SOCCopilotAgent(
                orchestrator=self,
                event_bus=self.event_bus,
                shared_memory=self.shared_memory,
            ),
        ]
        for agent in agents:
            self.register_agent(agent)

    def register_agent(self, agent: BaseAgent) -> None:
        """Register an agent instance with the orchestrator."""
        self._agents[agent.agent_id] = agent
        self._agent_type_index[agent.agent_type].append(agent.agent_id)
        log.debug("Agent registered", agent_id=agent.agent_id, agent_type=agent.agent_type)

    async def route_event(self, event: dict) -> Dict[str, AgentResult]:
        """
        Route an event to the appropriate agent(s) based on its type.

        Returns a dict mapping agent_id → AgentResult for each agent
        that processed the event.
        """
        event_type = event.get("type", event.get("event_type", "telemetry"))
        target_types = _EVENT_ROUTING.get(event_type, ["behavioral_anomaly"])

        results: Dict[str, AgentResult] = {}

        for agent_type in target_types:
            agent_ids = self._agent_type_index.get(agent_type, [])
            for aid in agent_ids:
                agent = self._agents.get(aid)
                if agent and agent.health_check():
                    result = await agent._safe_process(event)
                    results[aid] = result

        log.info(
            "Event routed",
            event_type=event_type,
            agents_invoked=len(results),
        )
        return results

    async def process_threat_pipeline(self, telemetry_event: dict) -> PipelineResult:
        """
        Execute the full threat-processing pipeline:
        1. Anomaly detection
        2. Threat attribution
        3. MITRE ATT&CK mapping
        4. Attack path prediction
        5. SOAR automated response

        Args:
            telemetry_event: Raw telemetry dict from an endpoint agent.

        Returns:
            PipelineResult with results from each stage.
        """
        self._pipeline_count += 1
        pipeline_id = f"PIPE-{self._pipeline_count:04d}-{uuid.uuid4().hex[:6]}"
        started_at = datetime.now(timezone.utc).isoformat()
        agent_results: Dict[str, AgentResult] = {}
        stages_completed: List[str] = []

        log.info("Threat pipeline started", pipeline_id=pipeline_id)

        # ── Stage 1: Anomaly Detection ───────────────────────────────────
        anomaly_agent = self._get_agent_by_type("behavioral_anomaly")
        anomaly_result = await anomaly_agent._safe_process(telemetry_event)
        agent_results["anomaly"] = anomaly_result
        stages_completed.append("anomaly_detection")

        anomaly_data = anomaly_result.data
        is_anomaly = anomaly_data.get("is_anomaly", False)

        if not is_anomaly:
            # Normal event — pipeline short-circuits here
            log.info("Pipeline short-circuit: event is normal", pipeline_id=pipeline_id)
            return PipelineResult(
                pipeline_id=pipeline_id,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                stages_completed=stages_completed,
                agent_results=agent_results,
                overall_risk_score=anomaly_data.get("anomaly_score", 0.0),
                recommended_actions=["continue_monitoring"],
            )

        # Enrich event with anomaly data for downstream agents
        enriched = {**telemetry_event, **anomaly_data}

        # ── Stage 2: Threat Attribution ──────────────────────────────────
        attribution_agent = self._get_agent_by_type("threat_attribution")
        attribution_result = await attribution_agent._safe_process(enriched)
        agent_results["attribution"] = attribution_result
        stages_completed.append("threat_attribution")

        # Merge attribution data
        attr_data = attribution_result.data
        primary_detail = attr_data.get("primary_detail") or {}
        enriched["matched_techniques"] = primary_detail.get("matched_techniques", [])
        enriched["apt_group"] = attr_data.get("primary_attribution", "unknown")

        # ── Stage 3: MITRE Mapping ───────────────────────────────────────
        mitre_agent = self._get_agent_by_type("mitre_mapping")
        mitre_result = await mitre_agent._safe_process(enriched)
        agent_results["mitre"] = mitre_result
        stages_completed.append("mitre_mapping")

        # ── Stage 4: Attack Path Prediction ──────────────────────────────
        path_agent = self._get_agent_by_type("attack_path_prediction")
        path_result = await path_agent._safe_process(enriched)
        agent_results["attack_path"] = path_result
        stages_completed.append("attack_path_prediction")

        # ── Stage 5: SOAR Automated Response ─────────────────────────────
        soar_agent = self._get_agent_by_type("soar_response")
        soar_result = await soar_agent._safe_process(enriched)
        agent_results["soar_response"] = soar_result
        stages_completed.append("soar_response")

        # ── Aggregate risk score ─────────────────────────────────────────
        anomaly_score = anomaly_data.get("anomaly_score", 0.0)
        attribution_conf = attr_data.get("primary_confidence", 0.0)
        kill_chain = mitre_result.data.get("kill_chain_progress", 0.0)
        path_risk = max(
            (p.get("risk_score", 0.0) for p in path_result.data.get("predicted_paths", [{}])),
            default=0.0,
        )

        overall_risk = round(
            anomaly_score * 0.30 + attribution_conf * 0.20 +
            kill_chain * 0.25 + path_risk * 0.25,
            4,
        )

        # Recommended actions based on overall risk
        recommended: List[str] = []
        if overall_risk >= 0.75:
            recommended = ["isolate_host", "block_ip", "disable_account", "forensic_snapshot", "page_soc"]
        elif overall_risk >= 0.50:
            recommended = ["block_ip", "enhanced_monitoring", "collect_evidence"]
        elif overall_risk >= 0.25:
            recommended = ["enhanced_monitoring", "watchlist_ip"]
        else:
            recommended = ["continue_monitoring"]

        completed_at = datetime.now(timezone.utc).isoformat()
        pipeline_result = PipelineResult(
            pipeline_id=pipeline_id,
            started_at=started_at,
            completed_at=completed_at,
            stages_completed=stages_completed,
            agent_results=agent_results,
            overall_risk_score=overall_risk,
            recommended_actions=recommended,
        )

        log.info(
            "Threat pipeline completed",
            pipeline_id=pipeline_id,
            stages=len(stages_completed),
            overall_risk=overall_risk,
            recommended_actions=recommended,
        )

        # Publish pipeline completion event
        await self.event_bus.publish("pipeline_complete", {
            "pipeline_id": pipeline_id,
            "overall_risk": overall_risk,
            "severity": anomaly_data.get("severity", "MEDIUM"),
        })

        return pipeline_result

    def get_agent_status(self) -> Dict[str, dict]:
        """Return health and stats for all registered agents."""
        return {aid: agent.stats() for aid, agent in self._agents.items()}

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Retrieve an agent by its ID."""
        return self._agents.get(agent_id)

    def _get_agent_by_type(self, agent_type: str) -> BaseAgent:
        """Return the first registered agent of the given type."""
        agent_ids = self._agent_type_index.get(agent_type, [])
        if not agent_ids:
            raise ValueError(f"No agent registered for type: {agent_type}")
        agent = self._agents.get(agent_ids[0])
        if agent is None:
            raise ValueError(f"Agent {agent_ids[0]} not found in registry")
        return agent

    def list_agents(self) -> List[dict]:
        """List all agents with their type and status."""
        return [
            {"agent_id": aid, "agent_type": a.agent_type, "status": a.status}
            for aid, a in self._agents.items()
        ]

    @property
    def pipeline_count(self) -> int:
        return self._pipeline_count
