'use client'

import { useEffect, useMemo, useState } from 'react'
import DetectionWorkbench from '../components/detection-workbench'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

type Summary = {
  total_detections: number
  coverage_percent: number
  average_detection_score: number
  attack_techniques_covered: number
  source_mode: string
  validation_failures: number
}

type Coverage = {
  by_tactic: Record<string, number>
  by_technique: Record<string, number>
  by_platform: Record<string, number>
  coverage_gaps: string[]
  weak_coverage: string[]
  high_risk_gaps: string[]
}

type ScoreRow = {
  id: string
  title: string
  coverage_score: number
  specificity_score: number
  metadata_score: number
  maintainability_score: number
  false_positive_risk: number
  false_positive_risk_level: string
  overall_score: number
  severity: string
  status: string
  recommendations?: string[]
}

type SourceStatus = {
  mode: string
  repo_url: string | null
  ref: string | null
  subdir: string | null
  resolved_path: string
  synced: boolean
}

type Reports = {
  valid: boolean
  files: string[]
  errors: Record<string, string>
  severity: Record<string, number>
  status: Record<string, number>
  score_distribution: Record<string, number>
  weak_detections: Array<{ id: string; title: string; score: number }>
}

type ReviewGap = {
  tactic: string
  priority: string
  recommended_source_path: string
  recommended_action: string
}

type ReviewWeakDetection = {
  id: string
  title: string
  overall_score: number
  severity: string
  status: string
  recommendations: string[]
}

type ReviewQueue = {
  high_risk_gaps: ReviewGap[]
  weak_detections: ReviewWeakDetection[]
}

type DashboardData = {
  summary: Summary
  source: SourceStatus
  coverage: Coverage
  scoring: ScoreRow[]
  review_queue: ReviewQueue
  reports: Reports
}

type DetectionCatalogEntry = {
  id: string
  name: string
  title: string
  description: string
  severity: string
  status: string
  domain: string[]
  platforms: string[]
  attack_techniques: string[]
  data_sources: string[]
  related_detections_count: number
  investigation_readiness_score: number
  content_kind: string
}

type DetectionCatalogResponse = {
  schema_version: string
  total: number
  detections: DetectionCatalogEntry[]
}

type InvestigationStep = {
  step: string
  priority: string
  rationale?: string | null
}

type DetectionWorkspace = {
  schema_version: string
  source_format: string
  normalized_from: string
  canonical_model_version: string
  detection: {
    id: string
    name: string
    title: string
    description: string
    severity: string
    status: string
    author: string
    domain: string[]
    platforms: string[]
  }
  overview: {
    purpose: string
    attack_mappings: {
      primary: {
        technique: string
        tactic: string
      }
      context: Array<{
        technique: string
        tactic?: string | null
        name?: string | null
        coverage: 'direct' | 'partial' | 'related' | 'gap'
        rationale?: string | null
      }>
    }
    data_sources: Array<{
      name: string
      kind: string
      provider?: string | null
      event_names: string[]
      notes?: string | null
    }>
    content_source: {
      path?: string | null
      kind?: string | null
    }
    query: {
      language?: string | null
      text?: string | null
    }
    detection_logic: {
      selection: Record<string, string | number | Array<string | number>>
      condition: string
    }
    references: string[]
  }
  investigation_guidance: {
    triage_steps: InvestigationStep[]
    investigation_steps: InvestigationStep[]
    escalation_guidance: string[]
    false_positives: string[]
  }
  threat_hunting: {
    related_hunts: Array<{
      name: string
      hypothesis?: string | null
      query_hint?: string | null
    }>
    related_detections: Array<{
      detection_id: string
      title: string
      severity?: string | null
      status?: string | null
      relationship: string
      rationale?: string | null
    }>
    adjacent_techniques: Array<{
      technique: string
      tactic?: string | null
      name?: string | null
      coverage: string
      rationale?: string | null
    }>
    coverage_gaps: Array<{
      technique: string
      tactic?: string | null
      name?: string | null
      coverage: string
      rationale?: string | null
    }>
  }
  dfir_guidance: {
    artifacts: Array<{
      name: string
      category: string
      path?: string | null
      notes?: string | null
    }>
    velociraptor_artifacts: string[]
  }
  cloud_security: {
    telemetry: Array<{
      provider: string
      source: string
      event_names: string[]
      notes?: string | null
    }>
  }
  response_actions: Array<{
    title: string
    priority: string
    description?: string | null
  }>
  related_detections: Array<{
    detection_id: string
    title: string
    severity?: string | null
    status?: string | null
    relationship: string
    rationale?: string | null
  }>
  heat_map: {
    direct: HeatMapEntry[]
    partial: HeatMapEntry[]
    related: HeatMapEntry[]
    gap: HeatMapEntry[]
  }
  relationship_graph: {
    nodes: Array<{ id: string; label: string; kind: string; severity?: string | null }>
    edges: Array<{ source: string; target: string; relationship: string; rationale?: string | null }>
  }
  knowledge_gaps: string[]
  conversions: {
    sigma: string
    splunk: string
    kql: string
    eql: string
  }
}

type HeatMapEntry = {
  technique: string
  tactic?: string | null
  name?: string | null
  coverage: 'direct' | 'partial' | 'related' | 'gap'
  rationale?: string | null
}

type ChartDatum = {
  name: string
  value: number
}

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? '/api'
const TACTIC_ORDER = [
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'exfiltration',
  'impact',
]

type ContentTab = {
  id: 'all' | 'detection' | 'investigation' | 'hunt' | 'learning'
  label: string
  kinds: string[]
}

const CONTENT_TABS: ContentTab[] = [
  { id: 'all', label: 'All Content', kinds: [] },
  { id: 'detection', label: 'Detections', kinds: ['detection'] },
  { id: 'investigation', label: 'Investigations', kinds: ['investigation', 'incident_response', 'forensics'] },
  { id: 'hunt', label: 'Threat Hunts', kinds: ['hunt'] },
  { id: 'learning', label: 'Learning Paths', kinds: ['learning_path', 'lab'] },
]

const shellStyle = {
  minHeight: '100vh',
  background: '#020617',
  color: '#e2e8f0',
  fontFamily: 'Inter, Arial, sans-serif',
  padding: '32px',
} as const
const cardStyle = {
  background: '#0f172a',
  border: '1px solid #1e293b',
  borderRadius: '16px',
  padding: '20px',
} as const

function tacticColor(value: number) {
  if (value >= 3) return '#16a34a'
  if (value >= 1) return '#f59e0b'
  return '#334155'
}

function severityBadgeColor(value: string) {
  if (value === 'critical') return '#7f1d1d'
  if (value === 'high') return '#78350f'
  if (value === 'medium') return '#1d4ed8'
  return '#14532d'
}

function heatBucketColor(bucket: HeatMapEntry['coverage']) {
  if (bucket === 'direct') return '#166534'
  if (bucket === 'partial') return '#a16207'
  if (bucket === 'related') return '#c2410c'
  return '#7f1d1d'
}

function coverageLabel(bucket: HeatMapEntry['coverage']) {
  if (bucket === 'direct') return 'Direct'
  if (bucket === 'partial') return 'Partial'
  if (bucket === 'related') return 'Related'
  return 'Gap'
}

function relationshipColor(relationship: string) {
  if (relationship === 'follow_on') return '#38bdf8'
  if (relationship === 'parent') return '#f59e0b'
  if (relationship === 'child') return '#22c55e'
  if (relationship === 'correlated') return '#a78bfa'
  return '#94a3b8'
}

function contentKindLabel(contentKind: string) {
  if (contentKind === 'detection') return 'Detection'
  if (contentKind === 'investigation') return 'Investigation'
  if (contentKind === 'incident_response') return 'Incident Response'
  if (contentKind === 'forensics') return 'Forensics'
  if (contentKind === 'hunt') return 'Threat Hunt'
  if (contentKind === 'learning_path') return 'Learning Path'
  if (contentKind === 'lab') return 'Lab'
  return contentKind.replace(/_/g, ' ')
}

export default function HomePage() {
  const [dashboard, setDashboard] = useState<DashboardData | null>(null)
  const [catalog, setCatalog] = useState<DetectionCatalogResponse | null>(null)
  const [selectedDetectionId, setSelectedDetectionId] = useState<string | null>(null)
  const [workspace, setWorkspace] = useState<DetectionWorkspace | null>(null)
  const [loadState, setLoadState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [workspaceState, setWorkspaceState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle')
  const [catalogQuery, setCatalogQuery] = useState('')
  const [activeCatalogTab, setActiveCatalogTab] = useState<(typeof CONTENT_TABS)[number]['id']>('all')

  useEffect(() => {
    async function loadInitialData() {
      try {
        setLoadState('loading')
        const [dashboardResponse, catalogResponse] = await Promise.all([
          fetch(`${API_BASE_URL}/dashboard`),
          fetch(`${API_BASE_URL}/detections/catalog`),
        ])

        if (!dashboardResponse.ok) {
          throw new Error(`dashboard request failed: ${dashboardResponse.status}`)
        }
        if (!catalogResponse.ok) {
          throw new Error(`catalog request failed: ${catalogResponse.status}`)
        }

        const dashboardBody: DashboardData = await dashboardResponse.json()
        const catalogBody: DetectionCatalogResponse = await catalogResponse.json()

        setDashboard(dashboardBody)
        setCatalog(catalogBody)
        setSelectedDetectionId(catalogBody.detections[0]?.id ?? null)
        setLoadState('ready')
      } catch {
        setDashboard(null)
        setCatalog(null)
        setLoadState('error')
      }
    }

    loadInitialData()
  }, [])

  useEffect(() => {
    if (!selectedDetectionId) return

    async function loadWorkspace() {
      try {
        setWorkspaceState('loading')
        const response = await fetch(`${API_BASE_URL}/detections/${selectedDetectionId}/workspace`)
        if (!response.ok) {
          throw new Error(`workspace request failed: ${response.status}`)
        }
        const body: DetectionWorkspace = await response.json()
        setWorkspace(body)
        setWorkspaceState('ready')
      } catch {
        setWorkspace(null)
        setWorkspaceState('error')
      }
    }

    loadWorkspace()
  }, [selectedDetectionId])

  const tacticData = useMemo<ChartDatum[]>(() => {
    if (!dashboard) return []
    return TACTIC_ORDER.map((name) => ({ name, value: dashboard.coverage.by_tactic[name] ?? 0 }))
  }, [dashboard])

  const scoreDistribution = useMemo<ChartDatum[]>(() => {
    if (!dashboard) return []
    return Object.entries(dashboard.reports.score_distribution).map(([name, value]) => ({ name, value }))
  }, [dashboard])

  const filteredDetections = useMemo(() => {
    const entries = catalog?.detections ?? []
    const activeTab = CONTENT_TABS.find((tab) => tab.id === activeCatalogTab)
    const query = catalogQuery.trim().toLowerCase()

    return entries.filter((entry) => {
      const allowedKinds = (activeTab?.kinds ?? []) as readonly string[]
      const kindMatch = !activeTab || allowedKinds.length === 0 || allowedKinds.includes(entry.content_kind)
      if (!kindMatch) return false
      if (!query) return true

      const haystack = [
        entry.name,
        entry.description,
        entry.severity,
        entry.status,
        entry.content_kind,
        ...entry.domain,
        ...entry.platforms,
        ...entry.attack_techniques,
        ...entry.data_sources,
      ]
        .join(' ')
        .toLowerCase()
      return haystack.includes(query)
    })
  }, [catalog, catalogQuery, activeCatalogTab])

  useEffect(() => {
    if (!filteredDetections.length) {
      setSelectedDetectionId(null)
      return
    }
    if (!selectedDetectionId || !filteredDetections.some((entry) => entry.id === selectedDetectionId)) {
      setSelectedDetectionId(filteredDetections[0].id)
    }
  }, [filteredDetections, selectedDetectionId])

  if (loadState === 'loading') {
    return (
      <main style={shellStyle}>
        <section style={{ maxWidth: '1440px', margin: '0 auto' }}>
          <Header />
          <div style={{ ...cardStyle, marginTop: '24px', color: '#94a3b8' }}>Loading detection catalog and workspace data...</div>
        </section>
      </main>
    )
  }

  if (loadState === 'error' || !dashboard || !catalog) {
    return (
      <main style={shellStyle}>
        <section style={{ maxWidth: '1440px', margin: '0 auto' }}>
          <Header />
          <div style={{ ...cardStyle, marginTop: '24px', borderColor: '#7f1d1d' }}>
            <div style={{ fontWeight: 700 }}>DetLab UI unavailable</div>
            <p style={{ color: '#94a3b8', marginBottom: 0 }}>
              The frontend could not load the FastAPI dashboard or detection catalog. Check the API service and retry.
            </p>
          </div>
        </section>
      </main>
    )
  }

  return (
    <main style={shellStyle}>
      <section style={{ maxWidth: '1440px', margin: '0 auto' }}>
        <Header />

        <nav style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginTop: '24px', marginBottom: '28px' }}>
          {['Detection Workspace', 'Documentation Framework', 'Coverage Overview', 'Score Review', 'Repository Source', 'Workbench'].map((item) => (
            <a
              key={item}
              href={`#${item.toLowerCase().replace(/\s+/g, '-')}`}
              style={{
                background: '#111827',
                color: '#cbd5e1',
                border: '1px solid #334155',
                padding: '10px 14px',
                borderRadius: '999px',
                textDecoration: 'none',
                fontSize: '0.95rem',
              }}
            >
              {item}
            </a>
          ))}
        </nav>

        <section id="detection-workspace">
          <h2 style={{ fontSize: '2rem', marginBottom: '8px' }}>Detection Workspace</h2>
          <p style={{ color: '#94a3b8', maxWidth: '900px' }}>
            Start from a detection, not a technique. Select a detection to see ATT&CK context, investigation guidance, DFIR artifacts, cloud telemetry, relationships, and response actions in one place.
          </p>

          <div
            id="documentation-framework"
            style={{
              ...cardStyle,
              marginTop: '16px',
              marginBottom: '16px',
              display: 'grid',
              gap: '16px',
            }}
          >
            <div>
              <h3 style={{ marginTop: 0, marginBottom: '8px' }}>Documentation Framework</h3>
              <p style={{ color: '#94a3b8', marginBottom: 0, maxWidth: '980px' }}>
                Every DetLab activity should become a reusable artifact. The standard workflow is Learn → Lab → Investigate → Detect → Hunt → Document → Publish.
              </p>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '12px' }}>
              {[
                'Learning paths',
                'Labs',
                'Incident response case studies',
                'Threat hunts',
                'Detection engineering',
                'AWS security learning',
                'flaws.cloud case studies',
                'Portfolio-ready artifacts',
              ].map((item) => (
                <div key={item} style={{ background: '#111827', border: '1px solid #334155', borderRadius: '12px', padding: '12px' }}>
                  {item}
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '0.9fr 1.6fr', gap: '16px', alignItems: 'start', marginTop: '16px' }}>
            <div style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
                <div>
                  <h3 style={{ margin: 0 }}>Detection Catalog</h3>
                  <p style={{ color: '#94a3b8', marginBottom: 0 }}>{catalog.total} detections available</p>
                </div>
                <span style={{ background: '#111827', border: '1px solid #334155', borderRadius: '999px', padding: '6px 10px', fontSize: '0.8rem' }}>
                  detection first
                </span>
              </div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '16px' }}>
                {CONTENT_TABS.map((tab) => {
                  const active = tab.id === activeCatalogTab
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveCatalogTab(tab.id)}
                      style={{
                        background: active ? '#0f172a' : '#111827',
                        color: active ? '#e0f2fe' : '#cbd5e1',
                        border: active ? '1px solid #38bdf8' : '1px solid #334155',
                        borderRadius: '999px',
                        padding: '8px 12px',
                        cursor: 'pointer',
                        fontSize: '0.85rem',
                      }}
                    >
                      {tab.label}
                    </button>
                  )
                })}
              </div>
              <input
                value={catalogQuery}
                onChange={(event) => setCatalogQuery(event.target.value)}
                placeholder="Search PowerShell, rundll32, credential access, AWS..."
                style={{
                  width: '100%',
                  marginTop: '16px',
                  background: '#020617',
                  color: '#e2e8f0',
                  border: '1px solid #334155',
                  borderRadius: '12px',
                  padding: '12px 14px',
                  boxSizing: 'border-box',
                }}
              />
              <div style={{ display: 'grid', gap: '12px', marginTop: '16px', maxHeight: '980px', overflowY: 'auto', paddingRight: '4px' }}>
                {filteredDetections.map((entry) => {
                  const selected = entry.id === selectedDetectionId
                  return (
                    <button
                      key={entry.id}
                      onClick={() => setSelectedDetectionId(entry.id)}
                      style={{
                        textAlign: 'left',
                        background: selected ? '#111827' : '#020617',
                        color: '#e2e8f0',
                        border: selected ? '1px solid #38bdf8' : '1px solid #1e293b',
                        borderRadius: '14px',
                        padding: '16px',
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center' }}>
                        <div style={{ fontWeight: 700 }}>{entry.name}</div>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap', justifyContent: 'end' }}>
                          <Tag label={contentKindLabel(entry.content_kind)} />
                          <SeverityBadge value={entry.severity} />
                        </div>
                      </div>
                      <div style={{ color: '#94a3b8', fontSize: '0.92rem', marginTop: '8px' }}>{entry.description}</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '12px' }}>
                        {entry.domain.map((value) => (
                          <Tag key={value} label={value} />
                        ))}
                        {entry.platforms.map((value) => (
                          <Tag key={value} label={value} />
                        ))}
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '12px', color: '#cbd5e1', fontSize: '0.86rem' }}>
                        <div>ATT&CK: {entry.attack_techniques.join(', ')}</div>
                        <div>Related: {entry.related_detections_count}</div>
                        <div>Status: {entry.status}</div>
                        <div>Readiness: {entry.investigation_readiness_score}%</div>
                      </div>
                    </button>
                  )
                })}
                {filteredDetections.length === 0 ? <div style={{ color: '#94a3b8' }}>No detections match that search.</div> : null}
              </div>
            </div>

            <div style={{ display: 'grid', gap: '16px' }}>
              {workspaceState === 'loading' ? <div style={cardStyle}>Loading detection workspace...</div> : null}
              {workspaceState === 'error' ? (
                <div style={{ ...cardStyle, borderColor: '#7f1d1d' }}>
                  The workspace for the selected detection could not be loaded.
                </div>
              ) : null}
              {workspace ? (
                <>
                  <div style={cardStyle}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', alignItems: 'start', flexWrap: 'wrap' }}>
                      <div>
                        <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
                          {workspace.detection.id}
                        </div>
                        <h3 style={{ margin: '8px 0 8px', fontSize: '2rem' }}>{workspace.detection.name}</h3>
                        <p style={{ color: '#94a3b8', marginTop: 0, maxWidth: '880px' }}>{workspace.detection.description}</p>
                      </div>
                      <div style={{ display: 'grid', gap: '8px', justifyItems: 'end' }}>
                        <SeverityBadge value={workspace.detection.severity} />
                        <span style={{ background: '#111827', border: '1px solid #334155', borderRadius: '999px', padding: '6px 10px', fontSize: '0.8rem' }}>
                          {workspace.detection.status}
                        </span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '12px' }}>
                      {workspace.detection.domain.map((value) => (
                        <Tag key={value} label={value} />
                      ))}
                      {workspace.detection.platforms.map((value) => (
                        <Tag key={value} label={value} />
                      ))}
                      <Tag label={workspace.overview.attack_mappings.primary.technique} />
                      <Tag label={workspace.overview.attack_mappings.primary.tactic} />
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '12px', marginTop: '16px' }}>
                      <StatCard label="Purpose" value={contentKindLabel(String(workspace.overview.content_source.kind ?? 'detection'))} />
                      <StatCard label="Data Sources" value={String(workspace.overview.data_sources.length)} />
                      <StatCard label="Related Detections" value={String(workspace.related_detections.length)} />
                      <StatCard label="Source Format" value={workspace.source_format} />
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                    <div style={cardStyle}>
                      <h3 style={{ marginTop: 0 }}>Detection Overview</h3>
                      <OverviewBlock label="Purpose" value={workspace.overview.purpose} />
                      <OverviewBlock
                        label="Primary ATT&CK Mapping"
                        value={`${workspace.overview.attack_mappings.primary.technique} · ${workspace.overview.attack_mappings.primary.tactic}`}
                      />
                      <OverviewBlock
                        label="Content Source"
                        value={`${workspace.overview.content_source.kind ?? 'knowledge'}${workspace.overview.content_source.path ? ` · ${workspace.overview.content_source.path}` : ''}`}
                      />
                      <OverviewBlock label="Normalized From" value={workspace.normalized_from} />
                      <OverviewBlock label="Canonical Model Version" value={workspace.canonical_model_version} />
                      <OverviewList label="Data Sources" items={workspace.overview.data_sources.map((item) => `${item.name}${item.notes ? ` — ${item.notes}` : ''}`)} />
                      <OverviewList label="References" items={workspace.overview.references} />
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                      <div style={cardStyle}>
                        <h3 style={{ marginTop: 0 }}>Detection Logic & Query</h3>
                        {workspace.overview.query.text ? (
                          <>
                            <OverviewBlock label="Query Language" value={workspace.overview.query.language ?? 'plain text'} />
                            <pre
                              style={{
                                margin: '0 0 16px 0',
                                padding: '16px',
                                background: '#020617',
                                border: '1px solid #334155',
                                borderRadius: '14px',
                                overflowX: 'auto',
                                whiteSpace: 'pre-wrap',
                                color: '#e2e8f0',
                              }}
                            >
                              {workspace.overview.query.text}
                            </pre>
                          </>
                        ) : null}
                        <pre
                          style={{
                            margin: 0,
                            padding: '16px',
                            background: '#020617',
                            border: '1px solid #334155',
                            borderRadius: '14px',
                            overflowX: 'auto',
                            whiteSpace: 'pre-wrap',
                            color: '#e2e8f0',
                          }}
                        >
                          {JSON.stringify(workspace.overview.detection_logic, null, 2)}
                        </pre>
                      </div>

                      <div style={cardStyle}>
                        <h3 style={{ marginTop: 0 }}>Generated Conversions</h3>
                        <p style={{ color: '#94a3b8', marginTop: 0 }}>
                          Canonical detection content can be reviewed as generated Sigma, Splunk, KQL, and EQL without leaving the workspace.
                        </p>
                        <div style={{ display: 'grid', gap: '12px' }}>
                          {Object.entries(workspace.conversions).map(([label, content]) => (
                            <div key={label}>
                              <div style={{ color: '#94a3b8', fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '8px' }}>
                                {label}
                              </div>
                              <pre
                                style={{
                                  margin: 0,
                                  padding: '16px',
                                  background: '#020617',
                                  border: '1px solid #334155',
                                  borderRadius: '14px',
                                  overflowX: 'auto',
                                  whiteSpace: 'pre-wrap',
                                  color: '#e2e8f0',
                                  maxHeight: '220px',
                                }}
                              >
                                {content}
                              </pre>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 0.85fr', gap: '16px' }}>
                    <div style={cardStyle}>
                      <h3 style={{ marginTop: 0 }}>Investigation Guidance</h3>
                      <StepList title="Triage Checklist" steps={workspace.investigation_guidance.triage_steps} />
                      <StepList title="Investigation Steps" steps={workspace.investigation_guidance.investigation_steps} />
                      <OverviewList label="Escalation Guidance" items={workspace.investigation_guidance.escalation_guidance} />
                      <OverviewList label="Common False Positives" items={workspace.investigation_guidance.false_positives} />
                    </div>

                    <div style={cardStyle}>
                      <h3 style={{ marginTop: 0 }}>ATT&CK Heat Map</h3>
                      <p style={{ color: '#94a3b8', marginTop: 0 }}>
                        Visualize what this detection sees directly, what it only partially explains, what activity is adjacent, and where common attacker progression still has coverage gaps.
                      </p>
                      <AttackMatrix heatMap={workspace.heat_map} />
                      <div style={{ display: 'grid', gap: '10px', marginTop: '16px' }}>
                        <HeatMapSection title="Direct Coverage" items={workspace.heat_map.direct} />
                        <HeatMapSection title="Partial Coverage" items={workspace.heat_map.partial} />
                        <HeatMapSection title="Related Activity" items={workspace.heat_map.related} />
                        <HeatMapSection title="Common Progression Gaps" items={workspace.heat_map.gap} />
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                    <div style={cardStyle}>
                      <h3 style={{ marginTop: 0 }}>Threat Hunting & Related Detections</h3>
                      <OverviewList
                        label="Related Hunts"
                        items={workspace.threat_hunting.related_hunts.map((item) => `${item.name}${item.hypothesis ? ` — ${item.hypothesis}` : ''}`)}
                      />
                      <OverviewList
                        label="Related Detections"
                        items={workspace.related_detections.map((item) => `${item.title} · ${item.relationship}${item.rationale ? ` — ${item.rationale}` : ''}`)}
                      />
                      <OverviewList
                        label="Adjacent Techniques"
                        items={workspace.threat_hunting.adjacent_techniques.map((item) => `${item.technique}${item.name ? ` · ${item.name}` : ''}`)}
                      />
                    </div>

                    <div style={cardStyle}>
                      <h3 style={{ marginTop: 0 }}>DFIR & Cloud Guidance</h3>
                      <OverviewList
                        label="Artifacts"
                        items={workspace.dfir_guidance.artifacts.map((item) => `${item.name}${item.path ? ` · ${item.path}` : ''}${item.notes ? ` — ${item.notes}` : ''}`)}
                      />
                      <OverviewList label="Velociraptor" items={workspace.dfir_guidance.velociraptor_artifacts} />
                      <OverviewList
                        label="Cloud Telemetry"
                        items={workspace.cloud_security.telemetry.map((item) => `${item.provider} · ${item.source}${item.event_names.length ? ` · ${item.event_names.join(', ')}` : ''}${item.notes ? ` — ${item.notes}` : ''}`)}
                      />
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                    <div style={cardStyle}>
                      <h3 style={{ marginTop: 0 }}>Relationship Graph</h3>
                      <p style={{ color: '#94a3b8', marginTop: 0 }}>
                        Pivot through parent, child, correlated, and follow-on detections from the current investigation anchor.
                      </p>
                      <RelationshipGraph
                        detection={workspace.detection}
                        graph={workspace.relationship_graph}
                        onSelectDetection={(detectionId) => setSelectedDetectionId(detectionId)}
                      />
                    </div>

                    <div style={cardStyle}>
                      <h3 style={{ marginTop: 0 }}>Response & Knowledge Gaps</h3>
                      <OverviewList
                        label="Response Actions"
                        items={workspace.response_actions.map((item) => `${item.title}${item.description ? ` — ${item.description}` : ''}`)}
                      />
                      <OverviewList label="Knowledge Gaps" items={workspace.knowledge_gaps} />
                    </div>
                  </div>
                </>
              ) : null}
            </div>
          </div>
        </section>

        <section id="coverage-overview" style={{ marginTop: '36px' }}>
          <h2 style={{ fontSize: '2rem' }}>Coverage Overview</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '0.95fr 1.05fr', gap: '16px', marginTop: '16px' }}>
            <div style={cardStyle}>
              <h3 style={{ marginTop: 0 }}>ATT&CK Coverage</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '12px', marginTop: '16px' }}>
                {tacticData.map((item) => (
                  <div key={item.name} style={{ background: tacticColor(item.value), borderRadius: '14px', padding: '16px', minHeight: '92px' }}>
                    <div style={{ fontSize: '0.9rem', textTransform: 'capitalize' }}>{item.name}</div>
                    <div style={{ fontSize: '2rem', fontWeight: 700, marginTop: '8px' }}>{item.value}</div>
                  </div>
                ))}
              </div>
              <div style={{ width: '100%', height: 320, marginTop: '16px' }}>
                <ResponsiveContainer>
                  <BarChart data={tacticData} margin={{ top: 16, right: 16, left: 0, bottom: 60 }}>
                    <CartesianGrid stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="name" stroke="#cbd5e1" angle={-25} textAnchor="end" interval={0} height={80} />
                    <YAxis stroke="#cbd5e1" />
                    <Tooltip />
                    <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                      {tacticData.map((entry) => (
                        <Cell key={entry.name} fill={tacticColor(entry.value)} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div style={{ display: 'grid', gap: '16px' }}>
              <div style={cardStyle}>
                <h3 style={{ marginTop: 0 }}>Coverage Gaps</h3>
                <OverviewList label="Uncovered Tactics" items={dashboard.coverage.coverage_gaps} />
                <OverviewList label="High-Risk Gaps" items={dashboard.coverage.high_risk_gaps} />
                <OverviewList label="Weak Coverage" items={dashboard.coverage.weak_coverage} />
              </div>
              <div style={cardStyle}>
                <h3 style={{ marginTop: 0 }}>Program Summary</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '12px' }}>
                  <StatCard label="Detections" value={String(dashboard.summary.total_detections)} />
                  <StatCard label="Coverage %" value={`${dashboard.summary.coverage_percent}%`} />
                  <StatCard label="Techniques" value={String(dashboard.summary.attack_techniques_covered)} />
                  <StatCard label="Avg Score" value={String(dashboard.summary.average_detection_score)} />
                  <StatCard label="Source Mode" value={dashboard.summary.source_mode} />
                  <StatCard label="Validation Failures" value={String(dashboard.summary.validation_failures)} />
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="score-review" style={{ marginTop: '36px' }}>
          <h2 style={{ fontSize: '2rem' }}>Score Review</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '0.9fr 1.1fr', gap: '16px', marginTop: '16px' }}>
            <div style={cardStyle}>
              <h3 style={{ marginTop: 0 }}>Score Distribution</h3>
              <div style={{ width: '100%', height: 280 }}>
                <ResponsiveContainer>
                  <BarChart data={scoreDistribution}>
                    <CartesianGrid stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="name" stroke="#cbd5e1" />
                    <YAxis stroke="#cbd5e1" allowDecimals={false} />
                    <Tooltip />
                    <Bar dataKey="value" fill="#38bdf8" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div style={{ ...cardStyle, overflowX: 'auto' }}>
              <h3 style={{ marginTop: 0 }}>Detection Score View</h3>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr>
                    {['Detection', 'Coverage', 'Specificity', 'Documentation', 'FP Risk', 'Overall'].map((label) => (
                      <th key={label} style={{ textAlign: 'left', color: '#93c5fd', fontSize: '0.8rem', paddingBottom: '10px', borderBottom: '1px solid #334155' }}>
                        {label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {dashboard.scoring.map((row) => (
                    <tr key={`${row.id}-${row.title}`}>
                      <td style={{ padding: '14px 8px 14px 0', borderBottom: '1px solid #1e293b' }}>{row.title}</td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b' }}>{row.coverage_score}</td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b' }}>{row.specificity_score}</td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b' }}>{row.metadata_score}</td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b' }}>{row.false_positive_risk_level}</td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b', fontWeight: 700 }}>{row.overall_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section id="repository-source" style={{ marginTop: '36px' }}>
          <h2 style={{ fontSize: '2rem' }}>Repository Source</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr', gap: '16px', marginTop: '16px' }}>
            <div style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                <h3 style={{ margin: 0 }}>Detection Content Source</h3>
                <Tag label={dashboard.source.synced ? 'synced' : dashboard.source.mode} />
              </div>
              <p style={{ color: '#94a3b8' }}>
                DetLab now reads detections from a directory-backed source instead of curated detection packs.
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <StatCard label="Mode" value={dashboard.source.mode} />
                <StatCard label="Ref" value={dashboard.source.ref ?? 'local'} />
              </div>
              <OverviewBlock label="Resolved Path" value={dashboard.source.resolved_path} />
              <OverviewBlock label="Directory" value={dashboard.source.subdir ?? 'detections'} />
              {dashboard.source.repo_url ? <OverviewBlock label="Repository" value={dashboard.source.repo_url} /> : null}
            </div>
            <div style={cardStyle}>
              <h3 style={{ marginTop: 0 }}>Gap Routing</h3>
              {dashboard.review_queue.high_risk_gaps.length > 0 ? (
                <div style={{ display: 'grid', gap: '10px' }}>
                  {dashboard.review_queue.high_risk_gaps.map((gap) => (
                    <div key={gap.tactic} style={{ background: '#111827', border: '1px solid #334155', borderRadius: '12px', padding: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center' }}>
                        <div style={{ fontWeight: 700 }}>{gap.tactic}</div>
                        <Tag label={gap.priority} />
                      </div>
                      <div style={{ color: '#94a3b8', marginTop: '6px' }}>{gap.recommended_action}</div>
                      <div style={{ marginTop: '8px', fontFamily: 'monospace', fontSize: '0.9rem', color: '#cbd5e1' }}>
                        {gap.recommended_source_path}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ color: '#94a3b8' }}>No high-risk gaps queued right now.</div>
              )}
            </div>
          </div>
        </section>

        <section id="workbench" style={{ marginTop: '36px' }}>
          <h2 style={{ fontSize: '2rem' }}>Validation & Conversion Workbench</h2>
          <p style={{ color: '#94a3b8', maxWidth: '900px' }}>
            Keep the existing detection authoring loop available while the product pivots toward a detection-first investigation experience.
          </p>
          <DetectionWorkbench />
        </section>
      </section>
    </main>
  )
}

function Header() {
  return (
    <>
      <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
        Detection Engineering, Threat Hunting, DFIR & Documentation
      </div>
      <h1 style={{ fontSize: '3rem', margin: '12px 0 8px' }}>DetLab</h1>
      <p style={{ color: '#94a3b8', fontSize: '1.1rem', maxWidth: '880px' }}>
        A detection-first knowledge platform: build detections, document labs and investigations, pivot through ATT&CK context, collect the right evidence, and publish reusable security artifacts.
      </p>
    </>
  )
}

function Tag({ label }: { label: string }) {
  return (
    <span style={{ background: '#111827', border: '1px solid #334155', padding: '4px 10px', borderRadius: '999px', fontSize: '0.8rem' }}>
      {label}
    </span>
  )
}

function SeverityBadge({ value }: { value: string }) {
  return (
    <span style={{ background: severityBadgeColor(value), padding: '4px 10px', borderRadius: '999px', fontSize: '0.8rem', textTransform: 'uppercase' }}>
      {value}
    </span>
  )
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '12px', padding: '12px' }}>
      <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>{label}</div>
      <div style={{ marginTop: '6px', fontWeight: 700 }}>{value}</div>
    </div>
  )
}

function OverviewBlock({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ marginTop: '14px' }}>
      <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>{label}</div>
      <div style={{ marginTop: '4px' }}>{value}</div>
    </div>
  )
}

function OverviewList({ label, items }: { label: string; items: string[] }) {
  return (
    <div style={{ marginTop: '14px' }}>
      <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>{label}</div>
      {items.length > 0 ? (
        <ul style={{ marginBottom: 0 }}>
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <div style={{ marginTop: '6px', color: '#94a3b8' }}>None yet</div>
      )}
    </div>
  )
}

function StepList({ title, steps }: { title: string; steps: InvestigationStep[] }) {
  return (
    <div style={{ marginTop: '14px' }}>
      <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>{title}</div>
      {steps.length > 0 ? (
        <div style={{ display: 'grid', gap: '10px', marginTop: '10px' }}>
          {steps.map((step) => (
            <div key={`${title}-${step.step}`} style={{ background: '#111827', border: '1px solid #334155', borderRadius: '12px', padding: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center' }}>
                <div style={{ fontWeight: 700 }}>{step.step}</div>
                <Tag label={step.priority} />
              </div>
              {step.rationale ? <div style={{ color: '#94a3b8', marginTop: '6px' }}>{step.rationale}</div> : null}
            </div>
          ))}
        </div>
      ) : (
        <div style={{ marginTop: '6px', color: '#94a3b8' }}>None yet</div>
      )}
    </div>
  )
}

function AttackMatrix({ heatMap }: { heatMap: DetectionWorkspace['heat_map'] }) {
  const entries = [...heatMap.direct, ...heatMap.partial, ...heatMap.related, ...heatMap.gap]
  const byTactic = TACTIC_ORDER.map((tactic) => ({
    tactic,
    items: entries.filter((entry) => entry.tactic === tactic),
  }))

  return (
    <div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
        {(['direct', 'partial', 'related', 'gap'] as HeatMapEntry['coverage'][]).map((bucket) => (
          <div key={bucket} style={{ display: 'flex', alignItems: 'center', gap: '8px', background: '#111827', border: '1px solid #334155', borderRadius: '999px', padding: '6px 10px', fontSize: '0.8rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '999px', background: heatBucketColor(bucket), display: 'inline-block' }} />
            {coverageLabel(bucket)}
          </div>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '10px' }}>
        {byTactic.map(({ tactic, items }) => (
          <div key={tactic} style={{ background: '#111827', border: '1px solid #1e293b', borderRadius: '14px', padding: '12px', minHeight: '136px' }}>
            <div style={{ color: '#93c5fd', fontSize: '0.8rem', textTransform: 'capitalize' }}>{tactic}</div>
            <div style={{ marginTop: '10px', display: 'grid', gap: '8px' }}>
              {items.length > 0 ? (
                items.map((item) => (
                  <div key={`${tactic}-${item.technique}-${item.name ?? ''}`} style={{ background: heatBucketColor(item.coverage), borderRadius: '10px', padding: '8px 10px' }}>
                    <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{item.technique}</div>
                    <div style={{ fontSize: '0.78rem', color: '#e2e8f0', marginTop: '2px' }}>{item.name ?? coverageLabel(item.coverage)}</div>
                  </div>
                ))
              ) : (
                <div style={{ color: '#64748b', fontSize: '0.84rem' }}>No mapped visibility</div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function RelationshipGraph({
  detection,
  graph,
  onSelectDetection,
}: {
  detection: DetectionWorkspace['detection']
  graph: DetectionWorkspace['relationship_graph']
  onSelectDetection: (detectionId: string) => void
}) {
  const relatedNodes = graph.nodes.filter((node) => node.id !== detection.id)
  const positionedNodes = relatedNodes.map((node, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(relatedNodes.length, 1) - Math.PI / 2
    const radius = relatedNodes.length > 3 ? 146 : 126
    return {
      ...node,
      x: 190 + Math.cos(angle) * radius,
      y: 170 + Math.sin(angle) * radius,
    }
  })

  return (
    <div>
      {positionedNodes.length > 0 ? (
        <>
          <div style={{ position: 'relative', minHeight: '340px', background: '#020617', border: '1px solid #334155', borderRadius: '16px', overflow: 'hidden' }}>
            <svg viewBox="0 0 380 340" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }} aria-hidden="true">
              {positionedNodes.map((node) => {
                const edge = graph.edges.find((item) => item.target === node.id)
                return (
                  <g key={`edge-${node.id}`}>
                    <line x1="190" y1="170" x2={node.x} y2={node.y} stroke={relationshipColor(edge?.relationship ?? 'similar')} strokeWidth="2.5" opacity="0.9" />
                    <circle cx={node.x} cy={node.y} r="4" fill={relationshipColor(edge?.relationship ?? 'similar')} />
                  </g>
                )
              })}
            </svg>

            <div style={{ position: 'absolute', left: '50%', top: '50%', transform: 'translate(-50%, -50%)', width: '132px', zIndex: 2 }}>
              <div style={{ background: '#0f172a', border: '2px solid #38bdf8', borderRadius: '16px', padding: '12px', textAlign: 'center', boxShadow: '0 10px 30px rgba(2, 6, 23, 0.45)' }}>
                <div style={{ color: '#38bdf8', fontSize: '0.74rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Selected</div>
                <div style={{ fontWeight: 700, marginTop: '6px', fontSize: '0.9rem' }}>{detection.name}</div>
                <div style={{ marginTop: '8px' }}>
                  <SeverityBadge value={detection.severity} />
                </div>
              </div>
            </div>

            {positionedNodes.map((node) => {
              const edge = graph.edges.find((item) => item.target === node.id)
              return (
                <button
                  key={node.id}
                  onClick={() => onSelectDetection(node.id)}
                  style={{
                    position: 'absolute',
                    left: `${node.x}px`,
                    top: `${node.y}px`,
                    transform: 'translate(-50%, -50%)',
                    width: '126px',
                    background: '#111827',
                    color: '#e2e8f0',
                    border: `1px solid ${relationshipColor(edge?.relationship ?? 'similar')}`,
                    borderRadius: '14px',
                    padding: '10px',
                    cursor: 'pointer',
                    zIndex: 2,
                    boxShadow: '0 10px 24px rgba(2, 6, 23, 0.25)',
                  }}
                >
                  <div style={{ fontWeight: 700, fontSize: '0.84rem' }}>{node.label}</div>
                  <div style={{ marginTop: '6px', color: '#93c5fd', fontSize: '0.76rem' }}>{edge?.relationship ?? 'similar'}</div>
                </button>
              )
            })}
          </div>

          <div style={{ display: 'grid', gap: '10px', marginTop: '14px' }}>
            {graph.edges.map((edge) => (
              <button
                key={`${edge.source}-${edge.target}-${edge.relationship}`}
                onClick={() => onSelectDetection(edge.target)}
                style={{ background: '#111827', color: '#e2e8f0', border: `1px solid ${relationshipColor(edge.relationship)}`, borderRadius: '12px', padding: '12px', textAlign: 'left', cursor: 'pointer' }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center' }}>
                  <div style={{ fontWeight: 700 }}>{edge.target}</div>
                  <span style={{ color: relationshipColor(edge.relationship), fontSize: '0.82rem', textTransform: 'uppercase' }}>{edge.relationship}</span>
                </div>
                {edge.rationale ? <div style={{ color: '#94a3b8', marginTop: '6px' }}>{edge.rationale}</div> : null}
              </button>
            ))}
          </div>
        </>
      ) : (
        <div style={{ color: '#94a3b8' }}>No relationship graph edges are currently available.</div>
      )}
    </div>
  )
}

function HeatMapSection({ title, items }: { title: string; items: HeatMapEntry[] }) {
  return (
    <div>
      <div style={{ color: '#94a3b8', fontSize: '0.86rem', marginBottom: '8px' }}>{title}</div>
      {items.length > 0 ? (
        <div style={{ display: 'grid', gap: '8px' }}>
          {items.map((item) => (
            <div key={`${title}-${item.technique}-${item.name ?? ''}`} style={{ background: heatBucketColor(item.coverage), borderRadius: '12px', padding: '12px' }}>
              <div style={{ fontWeight: 700 }}>{item.technique}{item.name ? ` · ${item.name}` : ''}</div>
              {item.tactic ? <div style={{ fontSize: '0.86rem', marginTop: '4px' }}>{item.tactic}</div> : null}
              {item.rationale ? <div style={{ fontSize: '0.86rem', color: '#e2e8f0', marginTop: '6px' }}>{item.rationale}</div> : null}
            </div>
          ))}
        </div>
      ) : (
        <div style={{ color: '#94a3b8' }}>None</div>
      )}
    </div>
  )
}
