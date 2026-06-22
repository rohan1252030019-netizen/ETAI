"""
IMMUNEX Neo4j Client
====================
Production-grade Neo4j driver wrapper with connection pooling,
auto-reconnect with exponential backoff, and graceful fallback
to in-memory networkx when Neo4j is unavailable.
"""

from __future__ import annotations

import os
import time
import threading
from typing import Any, Optional

import networkx as nx

from utils.logger import log

# ─── Optional Neo4j Import ────────────────────────────────────────────────────

_NEO4J_AVAILABLE = False
try:
    from neo4j import GraphDatabase, Driver, Session  # type: ignore[import-untyped]
    from neo4j.exceptions import (  # type: ignore[import-untyped]
        ServiceUnavailable,
        AuthError,
        SessionExpired,
        Neo4jError,
    )
    _NEO4J_AVAILABLE = True
except ImportError:
    GraphDatabase = None  # type: ignore[assignment,misc]
    Driver = None  # type: ignore[assignment,misc]
    Session = None  # type: ignore[assignment,misc]
    ServiceUnavailable = Exception  # type: ignore[assignment,misc]
    AuthError = Exception  # type: ignore[assignment,misc]
    SessionExpired = Exception  # type: ignore[assignment,misc]
    Neo4jError = Exception  # type: ignore[assignment,misc]


# ─── Connection Configuration ─────────────────────────────────────────────────

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "immunex_default")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")
NEO4J_MAX_CONNECTION_POOL_SIZE = int(os.getenv("NEO4J_MAX_POOL_SIZE", "50"))
NEO4J_CONNECTION_TIMEOUT = int(os.getenv("NEO4J_CONNECTION_TIMEOUT", "5"))

# Reconnect backoff parameters
_MAX_RETRIES = 5
_BASE_BACKOFF_S = 1.0
_MAX_BACKOFF_S = 30.0


class Neo4jClient:
    """
    Thread-safe Neo4j driver wrapper.

    Falls back to an in-memory networkx DiGraph when the neo4j Python
    package is not installed or the Neo4j server is unreachable.

    Usage::

        client = Neo4jClient()
        client.create_node("Asset", {"ip": "10.0.0.1", "name": "SCADA-GW"})
        client.create_relationship("10.0.0.1", "10.0.0.2", "CONNECTS_TO", {"port": 502})
        results = client.run_query("MATCH (n:Asset) RETURN n.ip AS ip LIMIT 10")
        client.close()
    """

    def __init__(
        self,
        uri: str = NEO4J_URI,
        user: str = NEO4J_USER,
        password: str = NEO4J_PASSWORD,
        database: str = NEO4J_DATABASE,
    ) -> None:
        self._uri = uri
        self._user = user
        self._password = password
        self._database = database
        self._driver: Any = None
        self._connected = False
        self._lock = threading.Lock()

        # In-memory fallback graph
        self._fallback_graph: nx.DiGraph = nx.DiGraph()
        self._using_fallback = False

        self._connect()

    # ── Connection Management ─────────────────────────────────────────────────

    def _connect(self) -> None:
        """Attempt to establish a Neo4j connection with exponential backoff."""
        if not _NEO4J_AVAILABLE:
            log.warning(
                "neo4j Python driver not installed — using networkx fallback",
                subsystem="neo4j_client",
            )
            self._using_fallback = True
            return

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                self._driver = GraphDatabase.driver(
                    self._uri,
                    auth=(self._user, self._password),
                    max_connection_pool_size=NEO4J_MAX_CONNECTION_POOL_SIZE,
                    connection_timeout=NEO4J_CONNECTION_TIMEOUT,
                )
                # Verify connectivity
                self._driver.verify_connectivity()
                self._connected = True
                self._using_fallback = False
                log.info(
                    "Neo4j connection established",
                    uri=self._uri,
                    attempt=attempt,
                    subsystem="neo4j_client",
                )
                return
            except (ServiceUnavailable, AuthError, OSError) as exc:
                backoff = min(_BASE_BACKOFF_S * (2 ** (attempt - 1)), _MAX_BACKOFF_S)
                log.warning(
                    "Neo4j connection attempt failed — retrying",
                    attempt=attempt,
                    max_retries=_MAX_RETRIES,
                    backoff_s=backoff,
                    error=str(exc),
                    subsystem="neo4j_client",
                )
                time.sleep(backoff)
            except Exception as exc:
                log.error(
                    "Unexpected error connecting to Neo4j",
                    error=str(exc),
                    subsystem="neo4j_client",
                )
                break

        log.warning(
            "Neo4j unavailable after retries — falling back to networkx",
            max_retries=_MAX_RETRIES,
            subsystem="neo4j_client",
        )
        self._using_fallback = True

    def _ensure_session(self) -> Any:
        """
        Get a Neo4j session, reconnecting if the driver has been lost.

        Returns None if using fallback.
        """
        if self._using_fallback:
            return None

        if self._driver is None or not self._connected:
            self._connect()
            if self._using_fallback:
                return None

        try:
            return self._driver.session(database=self._database)
        except (ServiceUnavailable, SessionExpired) as exc:
            log.warning(
                "Neo4j session lost — attempting reconnect",
                error=str(exc),
                subsystem="neo4j_client",
            )
            self._connected = False
            self._connect()
            if self._using_fallback:
                return None
            return self._driver.session(database=self._database)

    @property
    def is_connected(self) -> bool:
        """Return True if actively connected to Neo4j, False if using fallback."""
        return self._connected and not self._using_fallback

    @property
    def using_fallback(self) -> bool:
        """Return True if operating in networkx fallback mode."""
        return self._using_fallback

    @property
    def fallback_graph(self) -> nx.DiGraph:
        """Direct access to the in-memory networkx graph (used by attack graph engine)."""
        return self._fallback_graph

    # ── Node Operations ───────────────────────────────────────────────────────

    def create_node(
        self,
        label: str,
        properties: dict[str, Any],
        merge_key: str = "id",
    ) -> dict[str, Any]:
        """
        Create or merge a node with the given label and properties.

        Args:
            label: Node label (e.g. 'Asset', 'Vulnerability').
            properties: Key-value properties for the node.
            merge_key: The property key used for MERGE (deduplication).

        Returns:
            The properties dict of the created/merged node.
        """
        with self._lock:
            if self._using_fallback:
                node_id = properties.get(merge_key, properties.get("ip", str(id(properties))))
                self._fallback_graph.add_node(
                    node_id, label=label, **properties
                )
                log.debug(
                    "Fallback: created node",
                    label=label,
                    node_id=node_id,
                    subsystem="neo4j_client",
                )
                return properties

            session = self._ensure_session()
            if session is None:
                # Fell back mid-operation
                return self.create_node(label, properties, merge_key)

            try:
                with session:
                    merge_val = properties.get(merge_key, "")
                    cypher = (
                        f"MERGE (n:{label} {{{merge_key}: $merge_val}}) "
                        f"SET n += $props "
                        f"RETURN n"
                    )
                    result = session.run(
                        cypher,
                        merge_val=merge_val,
                        props=properties,
                    )
                    record = result.single()
                    if record:
                        return dict(record["n"])
                    return properties
            except (ServiceUnavailable, SessionExpired, Neo4jError) as exc:
                log.error(
                    "Neo4j create_node failed — falling back",
                    error=str(exc),
                    subsystem="neo4j_client",
                )
                self._using_fallback = True
                return self.create_node(label, properties, merge_key)

    def create_relationship(
        self,
        source_key: str,
        target_key: str,
        rel_type: str,
        properties: Optional[dict[str, Any]] = None,
        source_label: str = "Asset",
        target_label: str = "Asset",
        merge_field: str = "id",
    ) -> dict[str, Any]:
        """
        Create a directed relationship between two nodes.

        Args:
            source_key: Merge-key value of the source node.
            target_key: Merge-key value of the target node.
            rel_type: Relationship type (e.g. 'CONNECTS_TO', 'EXPLOITS').
            properties: Optional relationship properties.
            source_label: Label of source node.
            target_label: Label of target node.
            merge_field: The property field used to identify nodes.

        Returns:
            Dict with source, target, type, and properties.
        """
        props = properties or {}

        with self._lock:
            if self._using_fallback:
                self._fallback_graph.add_edge(
                    source_key, target_key, rel_type=rel_type, **props
                )
                log.debug(
                    "Fallback: created relationship",
                    source=source_key,
                    target=target_key,
                    rel_type=rel_type,
                    subsystem="neo4j_client",
                )
                return {"source": source_key, "target": target_key, "type": rel_type, "properties": props}

            session = self._ensure_session()
            if session is None:
                return self.create_relationship(
                    source_key, target_key, rel_type, properties,
                    source_label, target_label, merge_field,
                )

            try:
                with session:
                    cypher = (
                        f"MATCH (a:{source_label} {{{merge_field}: $src}}), "
                        f"(b:{target_label} {{{merge_field}: $tgt}}) "
                        f"MERGE (a)-[r:{rel_type}]->(b) "
                        f"SET r += $props "
                        f"RETURN type(r) AS rel_type"
                    )
                    result = session.run(cypher, src=source_key, tgt=target_key, props=props)
                    record = result.single()
                    return {
                        "source": source_key,
                        "target": target_key,
                        "type": record["rel_type"] if record else rel_type,
                        "properties": props,
                    }
            except (ServiceUnavailable, SessionExpired, Neo4jError) as exc:
                log.error(
                    "Neo4j create_relationship failed — falling back",
                    error=str(exc),
                    subsystem="neo4j_client",
                )
                self._using_fallback = True
                return self.create_relationship(
                    source_key, target_key, rel_type, properties,
                    source_label, target_label, merge_field,
                )

    # ── Bulk Operations ───────────────────────────────────────────────────────

    def bulk_ingest_nodes(
        self,
        label: str,
        nodes: list[dict[str, Any]],
        merge_key: str = "id",
    ) -> int:
        """
        Bulk ingest a list of nodes using UNWIND for performance.

        Returns the count of nodes processed.
        """
        if not nodes:
            return 0

        with self._lock:
            if self._using_fallback:
                for node_props in nodes:
                    node_id = node_props.get(merge_key, node_props.get("ip", str(id(node_props))))
                    self._fallback_graph.add_node(node_id, label=label, **node_props)
                log.info(
                    "Fallback: bulk ingested nodes",
                    label=label,
                    count=len(nodes),
                    subsystem="neo4j_client",
                )
                return len(nodes)

            session = self._ensure_session()
            if session is None:
                return self.bulk_ingest_nodes(label, nodes, merge_key)

            try:
                with session:
                    cypher = (
                        f"UNWIND $batch AS row "
                        f"MERGE (n:{label} {{{merge_key}: row.{merge_key}}}) "
                        f"SET n += row "
                        f"RETURN count(n) AS cnt"
                    )
                    result = session.run(cypher, batch=nodes)
                    record = result.single()
                    count = record["cnt"] if record else len(nodes)
                    log.info(
                        "Neo4j: bulk ingested nodes",
                        label=label,
                        count=count,
                        subsystem="neo4j_client",
                    )
                    return count
            except (ServiceUnavailable, SessionExpired, Neo4jError) as exc:
                log.error(
                    "Neo4j bulk_ingest_nodes failed — falling back",
                    error=str(exc),
                    subsystem="neo4j_client",
                )
                self._using_fallback = True
                return self.bulk_ingest_nodes(label, nodes, merge_key)

    def bulk_ingest_relationships(
        self,
        relationships: list[dict[str, Any]],
        source_label: str = "Asset",
        target_label: str = "Asset",
        merge_field: str = "id",
    ) -> int:
        """
        Bulk ingest relationships. Each dict must have:
        'source', 'target', 'rel_type', and optionally 'properties'.

        Returns the count of relationships processed.
        """
        if not relationships:
            return 0

        with self._lock:
            if self._using_fallback:
                for rel in relationships:
                    props = rel.get("properties", {})
                    self._fallback_graph.add_edge(
                        rel["source"],
                        rel["target"],
                        rel_type=rel["rel_type"],
                        **props,
                    )
                log.info(
                    "Fallback: bulk ingested relationships",
                    count=len(relationships),
                    subsystem="neo4j_client",
                )
                return len(relationships)

            session = self._ensure_session()
            if session is None:
                return self.bulk_ingest_relationships(
                    relationships, source_label, target_label, merge_field
                )

            try:
                with session:
                    # Group by relationship type for efficient batching
                    by_type: dict[str, list[dict[str, Any]]] = {}
                    for rel in relationships:
                        by_type.setdefault(rel["rel_type"], []).append(rel)

                    total = 0
                    for rel_type, rels in by_type.items():
                        batch = [
                            {"src": r["source"], "tgt": r["target"], "props": r.get("properties", {})}
                            for r in rels
                        ]
                        cypher = (
                            f"UNWIND $batch AS row "
                            f"MATCH (a:{source_label} {{{merge_field}: row.src}}), "
                            f"(b:{target_label} {{{merge_field}: row.tgt}}) "
                            f"MERGE (a)-[r:{rel_type}]->(b) "
                            f"SET r += row.props "
                            f"RETURN count(r) AS cnt"
                        )
                        result = session.run(cypher, batch=batch)
                        record = result.single()
                        total += record["cnt"] if record else len(rels)

                    log.info(
                        "Neo4j: bulk ingested relationships",
                        count=total,
                        subsystem="neo4j_client",
                    )
                    return total
            except (ServiceUnavailable, SessionExpired, Neo4jError) as exc:
                log.error(
                    "Neo4j bulk_ingest_relationships failed — falling back",
                    error=str(exc),
                    subsystem="neo4j_client",
                )
                self._using_fallback = True
                return self.bulk_ingest_relationships(
                    relationships, source_label, target_label, merge_field
                )

    # ── Query Execution ───────────────────────────────────────────────────────

    def run_query(
        self,
        cypher: str,
        parameters: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a raw Cypher query and return results as a list of dicts.

        When using the networkx fallback, this returns an empty list
        (Cypher is not supported in fallback mode).
        """
        params = parameters or {}

        if self._using_fallback:
            log.debug(
                "Fallback mode — Cypher queries not supported; returning empty",
                subsystem="neo4j_client",
            )
            return []

        session = self._ensure_session()
        if session is None:
            return []

        try:
            with session:
                result = session.run(cypher, **params)
                return [dict(record) for record in result]
        except (ServiceUnavailable, SessionExpired, Neo4jError) as exc:
            log.error(
                "Neo4j run_query failed",
                error=str(exc),
                cypher_prefix=cypher[:80],
                subsystem="neo4j_client",
            )
            return []

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the Neo4j driver and release all pooled connections."""
        if self._driver is not None:
            try:
                self._driver.close()
                log.info("Neo4j driver closed", subsystem="neo4j_client")
            except Exception as exc:
                log.warning(
                    "Error closing Neo4j driver",
                    error=str(exc),
                    subsystem="neo4j_client",
                )
            finally:
                self._driver = None
                self._connected = False

    def __del__(self) -> None:
        """Best-effort cleanup on garbage collection."""
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        mode = "neo4j" if not self._using_fallback else "networkx-fallback"
        return f"<Neo4jClient mode={mode} uri={self._uri}>"
