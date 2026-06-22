'use client';

import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';

// ── TypeScript Interfaces ──────────────────────────────────────────────────
interface GraphNode {
  id: string;
  label: string;
  type: 'SERVER' | 'DEVICE' | 'PLC' | 'USER';
  ip: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  os?: string;
  sector?: string;
  cve_count?: number;
  risk_score?: number;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

interface GraphEdge {
  source: string;
  target: string;
  protocol?: string;
  port?: number;
  label?: string;
  is_attack_path?: boolean;
}

interface TopologyData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  attack_paths?: string[][];
}

// ── Constants ──────────────────────────────────────────────────────────────
const CRITICALITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

const NODE_SHAPES: Record<string, string> = {
  SERVER: 'rect',
  DEVICE: 'diamond',
  PLC: 'hexagon',
  USER: 'circle',
};

const API_BASE = 'http://localhost:8080';

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_TOPOLOGY: TopologyData = {
  nodes: [
    { id: 'gw-01', label: 'DMZ Gateway', type: 'SERVER', ip: '192.168.1.1', criticality: 'MEDIUM', os: 'Linux Alpine', sector: 'Infrastructure', cve_count: 3, risk_score: 45 },
    { id: 'web-srv', label: 'Web Server', type: 'SERVER', ip: '10.0.2.15', criticality: 'HIGH', os: 'Ubuntu 22.04', sector: 'Public Services', cve_count: 7, risk_score: 72 },
    { id: 'plc-01', label: 'SCADA PLC-01', type: 'PLC', ip: '10.0.50.10', criticality: 'CRITICAL', os: 'Siemens S7-1200', sector: 'Energy Grid', cve_count: 12, risk_score: 95 },
    { id: 'db-prod', label: 'Production DB', type: 'SERVER', ip: '10.0.10.5', criticality: 'CRITICAL', os: 'RHEL 9', sector: 'Data Center', cve_count: 5, risk_score: 88 },
    { id: 'ws-04', label: 'Analyst WS-04', type: 'DEVICE', ip: '10.0.5.40', criticality: 'LOW', os: 'Windows 11', sector: 'SOC', cve_count: 1, risk_score: 15 },
    { id: 'usr-admin', label: 'Admin User', type: 'USER', ip: '10.0.5.1', criticality: 'HIGH', os: 'Windows 11', sector: 'IT Admin', cve_count: 0, risk_score: 60 },
    { id: 'fw-01', label: 'Core Firewall', type: 'DEVICE', ip: '10.0.0.1', criticality: 'MEDIUM', os: 'Palo Alto PAN-OS', sector: 'Network', cve_count: 2, risk_score: 35 },
    { id: 'iot-hub', label: 'IoT Hub', type: 'DEVICE', ip: '10.0.60.1', criticality: 'HIGH', os: 'Embedded Linux', sector: 'IoT', cve_count: 9, risk_score: 78 },
  ],
  edges: [
    { source: 'gw-01', target: 'web-srv', protocol: 'HTTPS', port: 443, label: 'HTTPS (443)' },
    { source: 'gw-01', target: 'fw-01', protocol: 'TCP', port: 8443, label: 'Mgmt (8443)' },
    { source: 'web-srv', target: 'db-prod', protocol: 'SQL', port: 5432, label: 'SQL (5432)', is_attack_path: true },
    { source: 'fw-01', target: 'plc-01', protocol: 'Modbus', port: 502, label: 'Modbus (502)' },
    { source: 'ws-04', target: 'web-srv', protocol: 'SSH', port: 22, label: 'SSH (22)' },
    { source: 'usr-admin', target: 'db-prod', protocol: 'RDP', port: 3389, label: 'RDP (3389)', is_attack_path: true },
    { source: 'iot-hub', target: 'plc-01', protocol: 'MQTT', port: 1883, label: 'MQTT (1883)', is_attack_path: true },
    { source: 'web-srv', target: 'plc-01', protocol: 'TCP', port: 502, label: 'Lateral (502)', is_attack_path: true },
    { source: 'gw-01', target: 'iot-hub', protocol: 'HTTP', port: 80, label: 'HTTP (80)' },
  ],
  attack_paths: [['gw-01', 'web-srv', 'plc-01'], ['iot-hub', 'plc-01']],
};

// ── Component ──────────────────────────────────────────────────────────────
export default function AttackGraphViewer() {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animFrameRef = useRef<number>(0);

  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [dimensions, setDimensions] = useState({ width: 900, height: 600 });
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [animTick, setAnimTick] = useState(0);

  // Attack path node set for highlighting
  const attackPathNodes = useMemo(() => {
    if (!topology?.attack_paths) return new Set<string>();
    const s = new Set<string>();
    topology.attack_paths.forEach(path => path.forEach(id => s.add(id)));
    return s;
  }, [topology]);

  const attackPathEdges = useMemo(() => {
    if (!topology?.attack_paths) return new Set<string>();
    const s = new Set<string>();
    topology.attack_paths.forEach(path => {
      for (let i = 0; i < path.length - 1; i++) {
        s.add(`${path[i]}->${path[i + 1]}`);
      }
    });
    return s;
  }, [topology]);

  // Fetch topology data
  useEffect(() => {
    let cancelled = false;
    const fetchData = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${API_BASE}/api/v1/graph/topology`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: TopologyData = await res.json();
        if (!cancelled) {
          if (data.nodes && data.nodes.length > 0) {
            setTopology(data);
          } else {
            setTopology(MOCK_TOPOLOGY);
          }
        }
      } catch {
        if (!cancelled) setTopology(MOCK_TOPOLOGY);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetchData();
    return () => { cancelled = true; };
  }, []);

  // Measure container
  useEffect(() => {
    const obs = new ResizeObserver(entries => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) setDimensions({ width, height });
      }
    });
    if (containerRef.current) obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, []);

  // Force-directed layout
  useEffect(() => {
    if (!topology) return;
    const w = dimensions.width;
    const h = dimensions.height;
    const initialNodes: GraphNode[] = topology.nodes.map((n, i) => ({
      ...n,
      x: w / 2 + (Math.cos((i / topology.nodes.length) * Math.PI * 2) * Math.min(w, h) * 0.3),
      y: h / 2 + (Math.sin((i / topology.nodes.length) * Math.PI * 2) * Math.min(w, h) * 0.3),
      vx: 0,
      vy: 0,
    }));
    setNodes(initialNodes);

    let iterNodes = initialNodes.map(n => ({ ...n }));
    let iteration = 0;
    const maxIterations = 200;

    const simulate = () => {
      if (iteration >= maxIterations) return;
      const k = Math.sqrt((w * h) / iterNodes.length) * 0.8;
      const cool = 1 - iteration / maxIterations;

      // Repulsion
      for (let i = 0; i < iterNodes.length; i++) {
        iterNodes[i].vx = 0;
        iterNodes[i].vy = 0;
        for (let j = 0; j < iterNodes.length; j++) {
          if (i === j) continue;
          const dx = (iterNodes[i].x ?? 0) - (iterNodes[j].x ?? 0);
          const dy = (iterNodes[i].y ?? 0) - (iterNodes[j].y ?? 0);
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = (k * k) / dist;
          iterNodes[i].vx! += (dx / dist) * force * 0.05;
          iterNodes[i].vy! += (dy / dist) * force * 0.05;
        }
      }

      // Attraction
      const nodeMap = new Map(iterNodes.map(n => [n.id, n]));
      topology.edges.forEach(e => {
        const s = nodeMap.get(e.source);
        const t = nodeMap.get(e.target);
        if (!s || !t) return;
        const dx = (t.x ?? 0) - (s.x ?? 0);
        const dy = (t.y ?? 0) - (s.y ?? 0);
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (dist * dist) / k * 0.01;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        s.vx! += fx;
        s.vy! += fy;
        t.vx! -= fx;
        t.vy! -= fy;
      });

      // Center gravity
      iterNodes.forEach(n => {
        n.vx! += (w / 2 - (n.x ?? 0)) * 0.001;
        n.vy! += (h / 2 - (n.y ?? 0)) * 0.001;
      });

      // Update positions
      const padding = 50;
      iterNodes.forEach(n => {
        n.x = Math.max(padding, Math.min(w - padding, (n.x ?? 0) + n.vx! * cool));
        n.y = Math.max(padding, Math.min(h - padding, (n.y ?? 0) + n.vy! * cool));
      });

      iteration++;
      setNodes(iterNodes.map(n => ({ ...n })));
      if (iteration < maxIterations) {
        animFrameRef.current = requestAnimationFrame(simulate);
      }
    };

    animFrameRef.current = requestAnimationFrame(simulate);
    return () => cancelAnimationFrame(animFrameRef.current);
  }, [topology, dimensions]);

  // Animation tick for pulsing
  useEffect(() => {
    const interval = setInterval(() => setAnimTick(t => t + 1), 50);
    return () => clearInterval(interval);
  }, []);

  // Pan / Zoom handlers
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setTransform(prev => ({
      ...prev,
      scale: Math.max(0.3, Math.min(3, prev.scale * delta)),
    }));
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button === 0 && !(e.target as HTMLElement).closest('[data-node]')) {
      setIsPanning(true);
      setPanStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
    }
  }, [transform]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (isPanning) {
      setTransform(prev => ({
        ...prev,
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y,
      }));
    }
  }, [isPanning, panStart]);

  const handleMouseUp = useCallback(() => setIsPanning(false), []);

  // Node shape renderers
  const renderNodeShape = (node: GraphNode, radius: number) => {
    const color = CRITICALITY_COLORS[node.criticality] || '#6b7280';
    const isHovered = hoveredNode === node.id;
    const isAttackPath = attackPathNodes.has(node.id);
    const pulse = isAttackPath ? Math.sin(animTick * 0.1) * 0.3 + 0.7 : 1;
    const glowRadius = isHovered ? 20 : isAttackPath ? 12 : 0;

    const commonProps = {
      fill: `${color}22`,
      stroke: color,
      strokeWidth: isHovered ? 3 : 2,
      opacity: pulse,
      style: { filter: glowRadius > 0 ? `drop-shadow(0 0 ${glowRadius}px ${color})` : 'none' } as React.CSSProperties,
    };

    switch (NODE_SHAPES[node.type]) {
      case 'rect': {
        const s = radius * 1.4;
        return <rect x={-s / 2} y={-s / 2} width={s} height={s} rx={4} {...commonProps} />;
      }
      case 'diamond': {
        const s = radius * 1.2;
        return <polygon points={`0,${-s} ${s},0 0,${s} ${-s},0`} {...commonProps} />;
      }
      case 'hexagon': {
        const s = radius;
        const pts = Array.from({ length: 6 }, (_, i) => {
          const a = (Math.PI / 3) * i - Math.PI / 2;
          return `${Math.cos(a) * s},${Math.sin(a) * s}`;
        }).join(' ');
        return <polygon points={pts} {...commonProps} />;
      }
      default:
        return <circle r={radius} {...commonProps} />;
    }
  };

  // Icon inside nodes
  const renderNodeIcon = (node: GraphNode) => {
    const color = CRITICALITY_COLORS[node.criticality] || '#6b7280';
    const size = 12;
    switch (node.type) {
      case 'SERVER':
        return (
          <g>
            <rect x={-size / 2} y={-size / 2} width={size} height={size * 0.35} rx={1} fill={color} opacity={0.8} />
            <rect x={-size / 2} y={-size / 2 + size * 0.4} width={size} height={size * 0.35} rx={1} fill={color} opacity={0.6} />
          </g>
        );
      case 'PLC':
        return (
          <g>
            <circle r={size * 0.35} fill="none" stroke={color} strokeWidth={1.5} />
            <line x1={-size * 0.2} y1={0} x2={size * 0.2} y2={0} stroke={color} strokeWidth={1.5} />
            <line x1={0} y1={-size * 0.2} x2={0} y2={size * 0.2} stroke={color} strokeWidth={1.5} />
          </g>
        );
      case 'DEVICE':
        return (
          <g>
            <rect x={-size * 0.35} y={-size * 0.25} width={size * 0.7} height={size * 0.5} rx={2} fill="none" stroke={color} strokeWidth={1.5} />
            <line x1={-size * 0.15} y1={size * 0.35} x2={size * 0.15} y2={size * 0.35} stroke={color} strokeWidth={1.5} />
          </g>
        );
      case 'USER':
        return (
          <g>
            <circle cy={-size * 0.15} r={size * 0.2} fill={color} opacity={0.8} />
            <path d={`M${-size * 0.3},${size * 0.35} Q0,${size * 0.1} ${size * 0.3},${size * 0.35}`} fill="none" stroke={color} strokeWidth={1.5} />
          </g>
        );
      default:
        return null;
    }
  };

  const nodeMap = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes]);

  // ── Render ───────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={styles.container}>
        <div style={styles.header}>
          <div style={styles.headerIcon}>⬡</div>
          <h2 style={styles.headerTitle}>ATTACK GRAPH TOPOLOGY</h2>
        </div>
        <div style={styles.loadingContainer}>
          <div style={styles.spinner} />
          <span style={styles.loadingText}>Mapping network topology...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={styles.container}>
        <div style={styles.header}>
          <div style={styles.headerIcon}>⬡</div>
          <h2 style={styles.headerTitle}>ATTACK GRAPH TOPOLOGY</h2>
        </div>
        <div style={styles.errorContainer}>
          <span style={styles.errorText}>⚠ {error}</span>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={styles.headerIcon}>⬡</div>
          <h2 style={styles.headerTitle}>ATTACK GRAPH TOPOLOGY</h2>
        </div>
        <div style={styles.headerBadge}>
          {nodes.length} NODES • {topology?.edges.length || 0} EDGES
        </div>
      </div>

      {/* Legend */}
      <div style={styles.legend}>
        {Object.entries(CRITICALITY_COLORS).map(([level, color]) => (
          <div key={level} style={styles.legendItem}>
            <div style={{ ...styles.legendDot, backgroundColor: color }} />
            <span style={styles.legendLabel}>{level}</span>
          </div>
        ))}
        <div style={styles.legendDivider} />
        {Object.entries(NODE_SHAPES).map(([type]) => (
          <span key={type} style={styles.legendLabel}>{type}</span>
        ))}
      </div>

      {/* Graph + Details panel */}
      <div style={styles.graphWrapper}>
        <div
          ref={containerRef}
          style={styles.svgContainer}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          <svg
            ref={svgRef}
            width={dimensions.width}
            height={dimensions.height}
            style={{ cursor: isPanning ? 'grabbing' : 'grab' }}
          >
            <defs>
              <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                <polygon points="0 0, 8 3, 0 6" fill="#4b5563" />
              </marker>
              <marker id="arrowhead-attack" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                <polygon points="0 0, 8 3, 0 6" fill="#ef4444" />
              </marker>
              <radialGradient id="bg-gradient">
                <stop offset="0%" stopColor="#111827" />
                <stop offset="100%" stopColor="#0a0a1a" />
              </radialGradient>
              {/* Grid pattern */}
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" opacity="0.3" />
              </pattern>
            </defs>

            {/* Background */}
            <rect width={dimensions.width} height={dimensions.height} fill="url(#bg-gradient)" />
            <rect width={dimensions.width} height={dimensions.height} fill="url(#grid)" />

            <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.scale})`}>
              {/* Edges */}
              {topology?.edges.map((edge, i) => {
                const s = nodeMap.get(edge.source);
                const t = nodeMap.get(edge.target);
                if (!s || !t) return null;
                const isAttack = edge.is_attack_path || attackPathEdges.has(`${edge.source}->${edge.target}`);
                const midX = ((s.x ?? 0) + (t.x ?? 0)) / 2;
                const midY = ((s.y ?? 0) + (t.y ?? 0)) / 2 - 15;

                return (
                  <g key={`edge-${i}`}>
                    <line
                      x1={s.x ?? 0}
                      y1={s.y ?? 0}
                      x2={t.x ?? 0}
                      y2={t.y ?? 0}
                      stroke={isAttack ? '#ef4444' : '#374151'}
                      strokeWidth={isAttack ? 2.5 : 1}
                      strokeDasharray={isAttack ? '8 4' : 'none'}
                      markerEnd={isAttack ? 'url(#arrowhead-attack)' : 'url(#arrowhead)'}
                      opacity={isAttack ? 0.5 + Math.sin(animTick * 0.08) * 0.5 : 0.5}
                    />
                    {edge.label && (
                      <text x={midX} y={midY} fill="#6b7280" fontSize="9" textAnchor="middle" fontFamily="monospace">
                        {edge.label}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Nodes */}
              {nodes.map(node => {
                const radius = node.criticality === 'CRITICAL' ? 28 : node.criticality === 'HIGH' ? 24 : 20;
                return (
                  <g
                    key={node.id}
                    data-node={node.id}
                    transform={`translate(${node.x ?? 0}, ${node.y ?? 0})`}
                    style={{ cursor: 'pointer' }}
                    onClick={() => setSelectedNode(selectedNode?.id === node.id ? null : node)}
                    onMouseEnter={() => setHoveredNode(node.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                  >
                    {renderNodeShape(node, radius)}
                    {renderNodeIcon(node)}
                    <text
                      y={radius + 14}
                      fill="#e2e8f0"
                      fontSize="10"
                      textAnchor="middle"
                      fontFamily="monospace"
                      fontWeight="bold"
                    >
                      {node.label}
                    </text>
                    <text
                      y={radius + 26}
                      fill="#6b7280"
                      fontSize="8"
                      textAnchor="middle"
                      fontFamily="monospace"
                    >
                      {node.ip}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        {/* Details Panel */}
        {selectedNode && (
          <div style={styles.detailsPanel}>
            <div style={styles.detailsHeader}>
              <span style={styles.detailsTitle}>{selectedNode.label}</span>
              <button style={styles.closeBtn} onClick={() => setSelectedNode(null)}>✕</button>
            </div>
            <div style={styles.detailsDivider} />
            <div style={styles.detailRow}>
              <span style={styles.detailLabel}>TYPE</span>
              <span style={styles.detailValue}>{selectedNode.type}</span>
            </div>
            <div style={styles.detailRow}>
              <span style={styles.detailLabel}>IP</span>
              <span style={{ ...styles.detailValue, color: '#06b6d4' }}>{selectedNode.ip}</span>
            </div>
            <div style={styles.detailRow}>
              <span style={styles.detailLabel}>CRITICALITY</span>
              <span style={{
                ...styles.badge,
                backgroundColor: `${CRITICALITY_COLORS[selectedNode.criticality]}22`,
                color: CRITICALITY_COLORS[selectedNode.criticality],
                borderColor: CRITICALITY_COLORS[selectedNode.criticality],
              }}>
                {selectedNode.criticality}
              </span>
            </div>
            <div style={styles.detailRow}>
              <span style={styles.detailLabel}>OS</span>
              <span style={styles.detailValue}>{selectedNode.os || 'Unknown'}</span>
            </div>
            <div style={styles.detailRow}>
              <span style={styles.detailLabel}>SECTOR</span>
              <span style={styles.detailValue}>{selectedNode.sector || 'N/A'}</span>
            </div>
            <div style={styles.detailRow}>
              <span style={styles.detailLabel}>CVEs</span>
              <span style={{ ...styles.detailValue, color: (selectedNode.cve_count ?? 0) > 5 ? '#ef4444' : '#10b981' }}>
                {selectedNode.cve_count ?? 0}
              </span>
            </div>
            <div style={styles.detailRow}>
              <span style={styles.detailLabel}>RISK</span>
              <div style={{ flex: 1 }}>
                <div style={styles.riskBarBg}>
                  <div style={{
                    ...styles.riskBarFill,
                    width: `${selectedNode.risk_score ?? 0}%`,
                    backgroundColor: (selectedNode.risk_score ?? 0) > 70 ? '#ef4444' : (selectedNode.risk_score ?? 0) > 40 ? '#f59e0b' : '#10b981',
                  }} />
                </div>
                <span style={{ fontSize: '10px', color: '#9ca3af' }}>{selectedNode.risk_score ?? 0}/100</span>
              </div>
            </div>
            {attackPathNodes.has(selectedNode.id) && (
              <div style={styles.attackWarning}>
                ⚠ NODE IS IN ACTIVE ATTACK PATH
              </div>
            )}
          </div>
        )}
      </div>

      {/* Zoom controls */}
      <div style={styles.zoomControls}>
        <button style={styles.zoomBtn} onClick={() => setTransform(p => ({ ...p, scale: Math.min(3, p.scale * 1.2) }))}>+</button>
        <button style={styles.zoomBtn} onClick={() => setTransform(p => ({ ...p, scale: Math.max(0.3, p.scale * 0.8) }))}>−</button>
        <button style={styles.zoomBtn} onClick={() => setTransform({ x: 0, y: 0, scale: 1 })}>⊙</button>
      </div>
    </div>
  );
}

// ── Styles ─────────────────────────────────────────────────────────────────
const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    backgroundColor: '#0a0a1a',
    color: '#e2e8f0',
    fontFamily: '"JetBrains Mono", "Fira Code", monospace',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '16px 20px',
    borderBottom: '1px solid #1e293b44',
    flexShrink: 0,
  },
  headerIcon: {
    color: '#06b6d4',
    fontSize: '18px',
  },
  headerTitle: {
    fontSize: '13px',
    fontWeight: 700,
    letterSpacing: '0.1em',
    textTransform: 'uppercase' as const,
    margin: 0,
  },
  headerBadge: {
    fontSize: '10px',
    color: '#64748b',
    backgroundColor: '#111827',
    padding: '4px 10px',
    borderRadius: '6px',
    border: '1px solid #1e293b',
    letterSpacing: '0.05em',
  },
  legend: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '8px 20px',
    borderBottom: '1px solid #1e293b22',
    flexShrink: 0,
  },
  legendItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  },
  legendDot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
  },
  legendLabel: {
    fontSize: '9px',
    color: '#6b7280',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.05em',
  },
  legendDivider: {
    width: '1px',
    height: '14px',
    backgroundColor: '#1e293b',
  },
  graphWrapper: {
    flex: 1,
    display: 'flex',
    position: 'relative' as const,
    overflow: 'hidden',
  },
  svgContainer: {
    flex: 1,
    overflow: 'hidden',
    position: 'relative' as const,
  },
  detailsPanel: {
    width: '280px',
    backgroundColor: '#111827',
    borderLeft: '1px solid #1e293b',
    padding: '16px',
    overflowY: 'auto' as const,
    flexShrink: 0,
  },
  detailsHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '12px',
  },
  detailsTitle: {
    fontSize: '13px',
    fontWeight: 700,
    color: '#f1f5f9',
  },
  closeBtn: {
    background: 'none',
    border: '1px solid #374151',
    color: '#9ca3af',
    borderRadius: '4px',
    width: '24px',
    height: '24px',
    cursor: 'pointer',
    fontSize: '12px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  detailsDivider: {
    height: '1px',
    backgroundColor: '#1e293b',
    marginBottom: '12px',
  },
  detailRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '10px',
  },
  detailLabel: {
    fontSize: '9px',
    color: '#6b7280',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.08em',
    fontWeight: 700,
  },
  detailValue: {
    fontSize: '12px',
    color: '#cbd5e1',
  },
  badge: {
    fontSize: '9px',
    fontWeight: 700,
    padding: '2px 8px',
    borderRadius: '4px',
    border: '1px solid',
    letterSpacing: '0.05em',
  },
  riskBarBg: {
    width: '100%',
    height: '6px',
    backgroundColor: '#1e293b',
    borderRadius: '3px',
    overflow: 'hidden',
    marginBottom: '2px',
  },
  riskBarFill: {
    height: '100%',
    borderRadius: '3px',
    transition: 'width 0.6s ease',
  },
  attackWarning: {
    marginTop: '12px',
    padding: '8px 10px',
    backgroundColor: '#ef444418',
    border: '1px solid #ef444444',
    borderRadius: '6px',
    color: '#ef4444',
    fontSize: '10px',
    fontWeight: 700,
    textAlign: 'center' as const,
    letterSpacing: '0.05em',
  },
  zoomControls: {
    position: 'absolute' as const,
    bottom: '20px',
    right: '20px',
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '4px',
  },
  zoomBtn: {
    width: '32px',
    height: '32px',
    backgroundColor: '#111827',
    border: '1px solid #374151',
    borderRadius: '6px',
    color: '#e2e8f0',
    fontSize: '16px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  loadingContainer: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    justifyContent: 'center',
    gap: '12px',
  },
  spinner: {
    width: '32px',
    height: '32px',
    border: '3px solid #1e293b',
    borderTopColor: '#06b6d4',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
  },
  loadingText: {
    fontSize: '11px',
    color: '#64748b',
  },
  errorContainer: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  errorText: {
    color: '#ef4444',
    fontSize: '13px',
    padding: '16px 24px',
    backgroundColor: '#ef444410',
    border: '1px solid #ef444430',
    borderRadius: '8px',
  },
};
