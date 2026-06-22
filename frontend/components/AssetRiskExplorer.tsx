'use client';

import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';

// ── TypeScript Interfaces ──────────────────────────────────────────────────
interface CVEDetail {
  cve_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss_score: number;
  description: string;
  published: string;
  exploitable: boolean;
}

interface Asset {
  id: string;
  ip: string;
  hostname: string;
  sector: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cve_count: number;
  risk_score: number;
  os?: string;
  mac_address?: string;
  last_scan?: string;
  cves?: CVEDetail[];
}

interface ThreatInfo {
  cve_id: string;
  affected_assets: number;
  exploit_available: boolean;
  trending: boolean;
}

type SortField = 'ip' | 'hostname' | 'sector' | 'criticality' | 'cve_count' | 'risk_score';
type SortDirection = 'asc' | 'desc';

// ── Constants ──────────────────────────────────────────────────────────────
const API_BASE = 'http://localhost:8080';

const CRITICALITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

const CRITICALITY_ORDER: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const SECTORS = ['All', 'Energy Grid', 'Government', 'Healthcare', 'Education', 'Infrastructure', 'Finance'];
const CRITICALITY_LEVELS = ['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_ASSETS: Asset[] = [
  { id: 'a1', ip: '10.0.50.10', hostname: 'scada-plc-01', sector: 'Energy Grid', criticality: 'CRITICAL', cve_count: 12, risk_score: 95, os: 'Siemens S7-1200', last_scan: '2026-06-22T10:00:00Z', cves: [
    { cve_id: 'CVE-2026-1001', severity: 'CRITICAL', cvss_score: 9.8, description: 'Remote code execution in Siemens S7-1200 PLC firmware via crafted Modbus packets', published: '2026-05-15', exploitable: true },
    { cve_id: 'CVE-2026-1042', severity: 'HIGH', cvss_score: 8.2, description: 'Authentication bypass in SCADA communication protocol handler', published: '2026-04-20', exploitable: true },
    { cve_id: 'CVE-2025-9981', severity: 'MEDIUM', cvss_score: 5.6, description: 'Information disclosure through unencrypted telemetry data', published: '2025-12-01', exploitable: false },
  ]},
  { id: 'a2', ip: '10.0.10.5', hostname: 'db-production', sector: 'Government', criticality: 'CRITICAL', cve_count: 5, risk_score: 88, os: 'RHEL 9 / PostgreSQL 15', last_scan: '2026-06-22T09:30:00Z', cves: [
    { cve_id: 'CVE-2026-2101', severity: 'CRITICAL', cvss_score: 9.1, description: 'SQL injection in PostgreSQL 15 jsonb query parser', published: '2026-06-01', exploitable: true },
    { cve_id: 'CVE-2026-2050', severity: 'HIGH', cvss_score: 7.5, description: 'Privilege escalation through pg_dump utility', published: '2026-05-10', exploitable: false },
  ]},
  { id: 'a3', ip: '10.0.2.15', hostname: 'web-frontend', sector: 'Healthcare', criticality: 'HIGH', cve_count: 7, risk_score: 72, os: 'Ubuntu 22.04 / Nginx', last_scan: '2026-06-22T08:15:00Z', cves: [
    { cve_id: 'CVE-2026-3001', severity: 'HIGH', cvss_score: 7.8, description: 'Server-side request forgery in Nginx reverse proxy configuration', published: '2026-03-18', exploitable: true },
  ]},
  { id: 'a4', ip: '10.0.60.1', hostname: 'iot-gateway', sector: 'Infrastructure', criticality: 'HIGH', cve_count: 9, risk_score: 78, os: 'Embedded Linux 5.15', last_scan: '2026-06-21T22:00:00Z', cves: [
    { cve_id: 'CVE-2026-4010', severity: 'HIGH', cvss_score: 8.0, description: 'Buffer overflow in MQTT message handler', published: '2026-02-28', exploitable: true },
  ]},
  { id: 'a5', ip: '10.0.5.40', hostname: 'analyst-ws04', sector: 'Government', criticality: 'LOW', cve_count: 1, risk_score: 15, os: 'Windows 11 Pro', last_scan: '2026-06-22T07:00:00Z', cves: [
    { cve_id: 'CVE-2026-0101', severity: 'LOW', cvss_score: 3.2, description: 'UI spoofing in Windows notification center', published: '2026-01-15', exploitable: false },
  ]},
  { id: 'a6', ip: '10.0.0.1', hostname: 'core-firewall', sector: 'Infrastructure', criticality: 'MEDIUM', cve_count: 2, risk_score: 35, os: 'Palo Alto PAN-OS 11', last_scan: '2026-06-22T06:00:00Z', cves: [] },
  { id: 'a7', ip: '10.0.30.20', hostname: 'ehr-server', sector: 'Healthcare', criticality: 'HIGH', cve_count: 6, risk_score: 80, os: 'Windows Server 2022', last_scan: '2026-06-22T05:00:00Z', cves: [
    { cve_id: 'CVE-2026-5101', severity: 'CRITICAL', cvss_score: 9.4, description: 'Remote code execution in HL7 FHIR message parsing engine', published: '2026-06-10', exploitable: true },
  ]},
  { id: 'a8', ip: '10.0.40.5', hostname: 'lms-portal', sector: 'Education', criticality: 'MEDIUM', cve_count: 3, risk_score: 42, os: 'Ubuntu 24.04 / Apache', last_scan: '2026-06-22T04:00:00Z', cves: [] },
  { id: 'a9', ip: '10.0.20.10', hostname: 'mail-server', sector: 'Government', criticality: 'MEDIUM', cve_count: 4, risk_score: 55, os: 'Debian 12 / Postfix', last_scan: '2026-06-22T03:00:00Z', cves: [
    { cve_id: 'CVE-2026-6001', severity: 'MEDIUM', cvss_score: 6.1, description: 'SMTP header injection allowing mail relay abuse', published: '2026-04-05', exploitable: false },
  ]},
  { id: 'a10', ip: '10.0.70.15', hostname: 'grid-controller', sector: 'Energy Grid', criticality: 'CRITICAL', cve_count: 8, risk_score: 92, os: 'VxWorks 7', last_scan: '2026-06-22T02:00:00Z', cves: [
    { cve_id: 'CVE-2026-7001', severity: 'CRITICAL', cvss_score: 9.9, description: 'Unauthenticated access to power distribution control interface', published: '2026-06-18', exploitable: true },
  ]},
];

// ── Component ──────────────────────────────────────────────────────────────
export default function AssetRiskExplorer() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sectorFilter, setSectorFilter] = useState('All');
  const [criticalityFilter, setCriticalityFilter] = useState('All');
  const [sortField, setSortField] = useState<SortField>('risk_score');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [expandedAsset, setExpandedAsset] = useState<string | null>(null);
  const [animatedScores, setAnimatedScores] = useState<Record<string, number>>({});

  // Fetch data
  useEffect(() => {
    let cancelled = false;
    const fetchAssets = async () => {
      setLoading(true);
      try {
        const [inventoryRes, threatsRes] = await Promise.allSettled([
          fetch(`${API_BASE}/api/v1/cve/inventory`),
          fetch(`${API_BASE}/api/v1/cve/top-threats`),
        ]);
        let data: Asset[] = [];
        if (inventoryRes.status === 'fulfilled' && inventoryRes.value.ok) {
          data = await inventoryRes.value.json();
        }
        if (!cancelled) {
          setAssets(data.length > 0 ? data : MOCK_ASSETS);
        }
      } catch {
        if (!cancelled) setAssets(MOCK_ASSETS);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetchAssets();
    return () => { cancelled = true; };
  }, []);

  // Animate risk scores
  useEffect(() => {
    if (assets.length === 0) return;
    const targets: Record<string, number> = {};
    assets.forEach(a => { targets[a.id] = a.risk_score; });

    const init: Record<string, number> = {};
    assets.forEach(a => { init[a.id] = 0; });
    setAnimatedScores(init);

    let frame = 0;
    const maxFrames = 40;
    const animate = () => {
      frame++;
      const progress = Math.min(frame / maxFrames, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current: Record<string, number> = {};
      assets.forEach(a => { current[a.id] = Math.round(targets[a.id] * eased); });
      setAnimatedScores(current);
      if (frame < maxFrames) requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);
  }, [assets]);

  // Filtering and sorting
  const filteredAssets = useMemo(() => {
    let result = [...assets];
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(a =>
        a.ip.toLowerCase().includes(q) ||
        a.hostname.toLowerCase().includes(q) ||
        a.sector.toLowerCase().includes(q)
      );
    }
    if (sectorFilter !== 'All') {
      result = result.filter(a => a.sector === sectorFilter);
    }
    if (criticalityFilter !== 'All') {
      result = result.filter(a => a.criticality === criticalityFilter);
    }
    result.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'criticality') {
        cmp = (CRITICALITY_ORDER[a.criticality] || 0) - (CRITICALITY_ORDER[b.criticality] || 0);
      } else if (sortField === 'cve_count' || sortField === 'risk_score') {
        cmp = (a[sortField] as number) - (b[sortField] as number);
      } else {
        cmp = String(a[sortField]).localeCompare(String(b[sortField]));
      }
      return sortDirection === 'desc' ? -cmp : cmp;
    });
    return result;
  }, [assets, searchQuery, sectorFilter, criticalityFilter, sortField, sortDirection]);

  const handleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSortDirection(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  }, [sortField]);

  const getRiskColor = (score: number) => {
    if (score >= 80) return '#ef4444';
    if (score >= 60) return '#f97316';
    if (score >= 40) return '#f59e0b';
    return '#10b981';
  };

  const getSortIndicator = (field: SortField) => {
    if (sortField !== field) return '↕';
    return sortDirection === 'asc' ? '↑' : '↓';
  };

  // ── Render ───────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={styles.container}>
        <div style={styles.header}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: '#06b6d4', fontSize: '16px' }}>◈</span>
            <h2 style={styles.headerTitle}>ASSET RISK EXPLORER</h2>
          </div>
        </div>
        <div style={styles.loadingContainer}>
          <div style={styles.spinner} />
          <span style={{ fontSize: '11px', color: '#64748b' }}>Scanning asset inventory...</span>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ color: '#06b6d4', fontSize: '16px' }}>◈</span>
          <h2 style={styles.headerTitle}>ASSET RISK EXPLORER</h2>
        </div>
        <div style={styles.headerBadge}>
          {filteredAssets.length} / {assets.length} ASSETS
        </div>
      </div>

      {/* Filters */}
      <div style={styles.filtersRow}>
        <div style={styles.searchBox}>
          <span style={{ color: '#64748b', fontSize: '13px' }}>⌕</span>
          <input
            style={styles.searchInput}
            placeholder="Search IP, hostname, sector..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
        </div>
        <select
          style={styles.select}
          value={sectorFilter}
          onChange={e => setSectorFilter(e.target.value)}
        >
          {SECTORS.map(s => <option key={s} value={s}>{s === 'All' ? '▣ All Sectors' : s}</option>)}
        </select>
        <select
          style={styles.select}
          value={criticalityFilter}
          onChange={e => setCriticalityFilter(e.target.value)}
        >
          {CRITICALITY_LEVELS.map(c => <option key={c} value={c}>{c === 'All' ? '◉ All Levels' : c}</option>)}
        </select>
      </div>

      {/* Summary cards */}
      <div style={styles.summaryRow}>
        {[
          { label: 'Critical Assets', value: assets.filter(a => a.criticality === 'CRITICAL').length, color: '#ef4444' },
          { label: 'Total CVEs', value: assets.reduce((s, a) => s + a.cve_count, 0), color: '#f97316' },
          { label: 'Avg Risk Score', value: Math.round(assets.reduce((s, a) => s + a.risk_score, 0) / (assets.length || 1)), color: '#f59e0b' },
          { label: 'Sectors Monitored', value: new Set(assets.map(a => a.sector)).size, color: '#06b6d4' },
        ].map((card, i) => (
          <div key={i} style={styles.summaryCard}>
            <span style={styles.summaryLabel}>{card.label}</span>
            <span style={{ ...styles.summaryValue, color: card.color }}>{card.value}</span>
          </div>
        ))}
      </div>

      {/* Table */}
      <div style={styles.tableWrapper}>
        <table style={styles.table}>
          <thead>
            <tr>
              {([
                ['ip', 'ASSET IP'],
                ['hostname', 'HOSTNAME'],
                ['sector', 'SECTOR'],
                ['criticality', 'CRITICALITY'],
                ['cve_count', 'CVE COUNT'],
                ['risk_score', 'RISK SCORE'],
              ] as [SortField, string][]).map(([field, label]) => (
                <th
                  key={field}
                  style={styles.th}
                  onClick={() => handleSort(field)}
                >
                  {label} <span style={{ opacity: 0.5, marginLeft: '4px' }}>{getSortIndicator(field)}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredAssets.map(asset => (
              <React.Fragment key={asset.id}>
                <tr
                  style={{
                    ...styles.tr,
                    backgroundColor: expandedAsset === asset.id ? '#111827' : 'transparent',
                    cursor: 'pointer',
                  }}
                  onClick={() => setExpandedAsset(expandedAsset === asset.id ? null : asset.id)}
                >
                  <td style={styles.td}>
                    <span style={{ color: '#06b6d4', fontWeight: 600 }}>{asset.ip}</span>
                  </td>
                  <td style={styles.td}>
                    <span style={{ color: '#e2e8f0' }}>{asset.hostname}</span>
                  </td>
                  <td style={styles.td}>
                    <span style={styles.sectorBadge}>{asset.sector}</span>
                  </td>
                  <td style={styles.td}>
                    <span style={{
                      ...styles.critBadge,
                      backgroundColor: `${CRITICALITY_COLORS[asset.criticality]}18`,
                      color: CRITICALITY_COLORS[asset.criticality],
                      borderColor: `${CRITICALITY_COLORS[asset.criticality]}44`,
                    }}>
                      {asset.criticality}
                    </span>
                  </td>
                  <td style={styles.td}>
                    <span style={{ color: asset.cve_count > 5 ? '#ef4444' : '#9ca3af', fontWeight: 600 }}>
                      {asset.cve_count}
                    </span>
                  </td>
                  <td style={styles.td}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={styles.riskBarBg}>
                        <div style={{
                          height: '100%',
                          width: `${animatedScores[asset.id] ?? 0}%`,
                          borderRadius: '3px',
                          background: `linear-gradient(90deg, ${getRiskColor(asset.risk_score)}88, ${getRiskColor(asset.risk_score)})`,
                          transition: 'width 0.3s ease',
                        }} />
                      </div>
                      <span style={{ fontSize: '11px', color: getRiskColor(asset.risk_score), fontWeight: 700, minWidth: '24px' }}>
                        {animatedScores[asset.id] ?? 0}
                      </span>
                    </div>
                  </td>
                </tr>
                {/* Expanded CVE details */}
                {expandedAsset === asset.id && (
                  <tr>
                    <td colSpan={6} style={{ padding: 0 }}>
                      <div style={styles.expandedPanel}>
                        <div style={styles.expandedHeader}>
                          <span style={{ color: '#06b6d4', fontWeight: 700, fontSize: '11px' }}>
                            ▸ CVE DETAILS — {asset.hostname}
                          </span>
                          <span style={{ fontSize: '10px', color: '#64748b' }}>
                            OS: {asset.os || 'Unknown'} • Last Scan: {asset.last_scan ? new Date(asset.last_scan).toLocaleString() : 'N/A'}
                          </span>
                        </div>
                        {asset.cves && asset.cves.length > 0 ? (
                          <div style={styles.cveList}>
                            {asset.cves.map(cve => (
                              <div key={cve.cve_id} style={styles.cveCard}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                                  <span style={{ color: '#f1f5f9', fontWeight: 700, fontSize: '12px' }}>{cve.cve_id}</span>
                                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                                    <span style={{
                                      fontSize: '9px',
                                      padding: '2px 6px',
                                      borderRadius: '3px',
                                      fontWeight: 700,
                                      backgroundColor: `${CRITICALITY_COLORS[cve.severity]}18`,
                                      color: CRITICALITY_COLORS[cve.severity],
                                      border: `1px solid ${CRITICALITY_COLORS[cve.severity]}44`,
                                    }}>
                                      {cve.severity}
                                    </span>
                                    <span style={{ fontSize: '10px', color: '#f59e0b', fontWeight: 600 }}>
                                      CVSS {cve.cvss_score}
                                    </span>
                                    {cve.exploitable && (
                                      <span style={{
                                        fontSize: '9px',
                                        padding: '2px 6px',
                                        borderRadius: '3px',
                                        backgroundColor: '#ef444418',
                                        color: '#ef4444',
                                        fontWeight: 700,
                                      }}>
                                        EXPLOIT
                                      </span>
                                    )}
                                  </div>
                                </div>
                                <p style={{ fontSize: '11px', color: '#9ca3af', margin: 0, lineHeight: 1.5 }}>
                                  {cve.description}
                                </p>
                                <span style={{ fontSize: '9px', color: '#4b5563', marginTop: '4px', display: 'block' }}>
                                  Published: {cve.published}
                                </span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div style={{ padding: '16px', textAlign: 'center', color: '#4b5563', fontSize: '11px' }}>
                            No CVE details available for this asset.
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
        {filteredAssets.length === 0 && (
          <div style={styles.emptyState}>
            <span style={{ fontSize: '24px', marginBottom: '8px' }}>◇</span>
            <span style={{ color: '#64748b', fontSize: '12px' }}>No assets match the current filters.</span>
          </div>
        )}
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
  filtersRow: {
    display: 'flex',
    gap: '10px',
    padding: '12px 20px',
    borderBottom: '1px solid #1e293b22',
    flexShrink: 0,
    flexWrap: 'wrap' as const,
  },
  searchBox: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    backgroundColor: '#111827',
    border: '1px solid #1e293b',
    borderRadius: '8px',
    padding: '6px 12px',
    flex: 1,
    minWidth: '200px',
  },
  searchInput: {
    background: 'none',
    border: 'none',
    outline: 'none',
    color: '#e2e8f0',
    fontSize: '12px',
    fontFamily: 'inherit',
    width: '100%',
  },
  select: {
    backgroundColor: '#111827',
    color: '#e2e8f0',
    border: '1px solid #1e293b',
    borderRadius: '8px',
    padding: '6px 12px',
    fontSize: '11px',
    fontFamily: 'inherit',
    cursor: 'pointer',
    outline: 'none',
  },
  summaryRow: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, 1fr)',
    gap: '10px',
    padding: '12px 20px',
    flexShrink: 0,
  },
  summaryCard: {
    backgroundColor: '#111827',
    border: '1px solid #1e293b',
    borderRadius: '10px',
    padding: '12px 16px',
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '4px',
    backdropFilter: 'blur(8px)',
  },
  summaryLabel: {
    fontSize: '9px',
    color: '#64748b',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.08em',
    fontWeight: 700,
  },
  summaryValue: {
    fontSize: '22px',
    fontWeight: 800,
  },
  tableWrapper: {
    flex: 1,
    overflowY: 'auto' as const,
    padding: '0 20px 20px',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse' as const,
    fontSize: '12px',
  },
  th: {
    textAlign: 'left' as const,
    padding: '10px 12px',
    fontSize: '9px',
    fontWeight: 700,
    color: '#64748b',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.08em',
    borderBottom: '1px solid #1e293b',
    cursor: 'pointer',
    userSelect: 'none' as const,
    whiteSpace: 'nowrap' as const,
  },
  tr: {
    borderBottom: '1px solid #1e293b33',
    transition: 'background-color 0.15s ease',
  },
  td: {
    padding: '10px 12px',
    verticalAlign: 'middle' as const,
  },
  sectorBadge: {
    fontSize: '10px',
    color: '#8b5cf6',
    backgroundColor: '#8b5cf618',
    padding: '2px 8px',
    borderRadius: '4px',
    fontWeight: 600,
    border: '1px solid #8b5cf633',
  },
  critBadge: {
    fontSize: '9px',
    fontWeight: 700,
    padding: '2px 8px',
    borderRadius: '4px',
    border: '1px solid',
    letterSpacing: '0.05em',
  },
  riskBarBg: {
    flex: 1,
    height: '6px',
    backgroundColor: '#1e293b',
    borderRadius: '3px',
    overflow: 'hidden',
  },
  expandedPanel: {
    backgroundColor: '#0d1117',
    borderTop: '1px solid #1e293b44',
    borderBottom: '1px solid #1e293b44',
    padding: '12px 16px',
  },
  expandedHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '10px',
    paddingBottom: '8px',
    borderBottom: '1px solid #1e293b33',
  },
  cveList: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '8px',
  },
  cveCard: {
    backgroundColor: '#111827',
    border: '1px solid #1e293b',
    borderRadius: '8px',
    padding: '10px 14px',
  },
  emptyState: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    justifyContent: 'center',
    padding: '48px',
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
};
