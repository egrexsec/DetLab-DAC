'use client'

import { useEffect, useMemo, useState } from 'react'
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
  packs_installed: number
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
}

type PackRow = {
  name: string
  title: string
  version: string
  maintainer: string
  description: string
  platforms: string[]
  focus_areas: string[]
  average_score: number
  pack_health: string
  validation: {
    manifest_valid: boolean
    detections_valid: boolean
    detection_count: number
  }
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

type DashboardData = {
  summary: Summary
  coverage: Coverage
  scoring: ScoreRow[]
  packs: PackRow[]
  reports: Reports
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
  'command-and-control',
  'exfiltration',
  'impact',
]

function tacticColor(value: number) {
  if (value >= 3) return '#16a34a'
  if (value >= 1) return '#f59e0b'
  return '#334155'
}

function riskBadgeColor(level: string) {
  if (level === 'High') return '#7f1d1d'
  if (level === 'Medium') return '#78350f'
  return '#14532d'
}

function healthBadgeColor(level: string) {
  return level === 'healthy' ? '#14532d' : '#7f1d1d'
}

export default function HomePage() {
  const [dashboard, setDashboard] = useState<DashboardData | null>(null)

  useEffect(() => {
    async function fetchDashboard() {
      try {
        const response = await fetch(`${API_BASE_URL}/dashboard`)
        const data: DashboardData = await response.json()
        setDashboard(data)
      } catch {
        setDashboard(null)
      }
    }

    fetchDashboard()
  }, [])

  const tacticData = useMemo<ChartDatum[]>(() => {
    if (!dashboard) return []
    return TACTIC_ORDER.map((name) => ({ name, value: dashboard.coverage.by_tactic[name] ?? 0 }))
  }, [dashboard])

  const platformData = useMemo<ChartDatum[]>(() => {
    if (!dashboard) return []
    return Object.entries(dashboard.coverage.by_platform).map(([name, value]) => ({ name, value }))
  }, [dashboard])

  const scoreDistribution = useMemo<ChartDatum[]>(() => {
    if (!dashboard) return []
    return Object.entries(dashboard.reports.score_distribution).map(([name, value]) => ({ name, value }))
  }, [dashboard])

  return (
    <main
      style={{
        minHeight: '100vh',
        background: '#020617',
        color: '#e2e8f0',
        fontFamily: 'Inter, Arial, sans-serif',
        padding: '32px',
      }}
    >
      <section
        style={{
          maxWidth: '1400px',
          margin: '0 auto',
        }}
      >
        <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
          Detection Engineering Workbench
        </div>
        <h1 style={{ fontSize: '3rem', margin: '12px 0 8px' }}>DetLab</h1>
        <p style={{ color: '#94a3b8', fontSize: '1.1rem', maxWidth: '820px' }}>
          Build, validate, score, convert, test, and visualize detections from a single platform.
        </p>

        <nav
          style={{
            display: 'flex',
            gap: '12px',
            flexWrap: 'wrap',
            marginTop: '24px',
            marginBottom: '28px',
          }}
        >
          {['Dashboard', 'Detections', 'Coverage', 'Scoring', 'Packs', 'Reports'].map((item) => (
            <a
              key={item}
              href={`#${item.toLowerCase()}`}
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

        <section id="dashboard">
          <h2 style={{ fontSize: '2rem' }}>Overview</h2>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
              gap: '16px',
              marginTop: '16px',
            }}
          >
            {[
              ['Total Detections', dashboard?.summary.total_detections ?? 0],
              ['Coverage %', `${dashboard?.summary.coverage_percent ?? 0}%`],
              ['Average Detection Score', dashboard?.summary.average_detection_score ?? 0],
              ['ATT&CK Techniques Covered', dashboard?.summary.attack_techniques_covered ?? 0],
              ['Packs Installed', dashboard?.summary.packs_installed ?? 0],
              ['Validation Failures', dashboard?.summary.validation_failures ?? 0],
            ].map(([label, value]) => (
              <div key={String(label)} style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px' }}>
                <div style={{ color: '#94a3b8', fontSize: '0.92rem' }}>{label}</div>
                <div style={{ fontSize: '2.2rem', fontWeight: 700, marginTop: '8px' }}>{value}</div>
              </div>
            ))}
          </div>
        </section>

        <section id="detections" style={{ marginTop: '36px' }}>
          <h2 style={{ fontSize: '2rem' }}>Detections</h2>
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px', marginTop: '16px' }}>
            <p style={{ color: '#94a3b8', marginTop: 0 }}>
              Use the workbench to validate schemas, score quality, convert detections to backend-specific formats, and surface weak spots in the library.
            </p>
            <ul style={{ marginBottom: 0, color: '#cbd5e1' }}>
              <li>`detlab validate detections`</li>
              <li>`detlab score detections --format markdown --output reports/scores.md`</li>
              <li>`detlab attack report detections --format markdown --output reports/attack.md`</li>
              <li>`detlab convert detections/windows/encoded_powershell.yml --target splunk`</li>
            </ul>
          </div>
        </section>

        <section id="coverage" style={{ marginTop: '36px' }}>
          <h2 style={{ fontSize: '2rem' }}>ATT&CK Coverage</h2>
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px', marginTop: '16px' }}>
            <h3 style={{ marginTop: 0 }}>Heatmap</h3>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
                gap: '12px',
                marginTop: '16px',
              }}
            >
              {tacticData.map((item) => (
                <div key={item.name} style={{ background: tacticColor(item.value), borderRadius: '14px', padding: '16px', minHeight: '96px' }}>
                  <div style={{ fontSize: '0.92rem', textTransform: 'capitalize' }}>{item.name}</div>
                  <div style={{ fontSize: '2rem', fontWeight: 700, marginTop: '10px' }}>{item.value}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '16px', marginTop: '16px' }}>
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px' }}>
              <h3 style={{ marginTop: 0 }}>Coverage by Tactic</h3>
              <div style={{ width: '100%', height: 320 }}>
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
              <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px' }}>
                <h3 style={{ marginTop: 0 }}>Coverage Gaps</h3>
                <ul>
                  {(dashboard?.coverage.coverage_gaps ?? []).map((gap) => <li key={gap}>{gap}</li>)}
                </ul>
              </div>
              <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px' }}>
                <h3 style={{ marginTop: 0 }}>High-Risk Gaps</h3>
                <ul>
                  {(dashboard?.coverage.high_risk_gaps ?? []).map((gap) => <li key={gap}>{gap}</li>)}
                </ul>
              </div>
            </div>
          </div>
        </section>

        <section id="scoring" style={{ marginTop: '36px' }}>
          <h2 style={{ fontSize: '2rem' }}>Detection Scoring</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '0.9fr 1.1fr', gap: '16px', marginTop: '16px' }}>
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px' }}>
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

            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px', overflowX: 'auto' }}>
              <h3 style={{ marginTop: 0 }}>Detection Score View</h3>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr>
                    {['Detection Name', 'Coverage', 'Specificity', 'Documentation', 'False Positive Risk', 'Overall Score'].map((label) => (
                      <th key={label} style={{ textAlign: 'left', color: '#93c5fd', fontSize: '0.8rem', paddingBottom: '10px', borderBottom: '1px solid #334155' }}>{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(dashboard?.scoring ?? []).map((row) => (
                    <tr key={row.id + row.title}>
                      <td style={{ padding: '14px 8px 14px 0', borderBottom: '1px solid #1e293b' }}>{row.title}</td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b' }}>{row.coverage_score}</td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b' }}>{row.specificity_score}</td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b' }}>{row.metadata_score}</td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b' }}>
                        <span style={{ background: riskBadgeColor(row.false_positive_risk_level), padding: '4px 10px', borderRadius: '999px', fontSize: '0.8rem' }}>
                          {row.false_positive_risk_level}
                        </span>
                      </td>
                      <td style={{ padding: '14px 8px', borderBottom: '1px solid #1e293b', fontWeight: 700 }}>{row.overall_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section id="packs" style={{ marginTop: '36px' }}>
          <h2 style={{ fontSize: '2rem' }}>Detection Packs</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '16px', marginTop: '16px' }}>
            {(dashboard?.packs ?? []).map((pack) => (
              <div key={pack.name} style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px' }}>
                  <h3 style={{ margin: 0 }}>{pack.title}</h3>
                  <span style={{ background: healthBadgeColor(pack.pack_health), padding: '4px 10px', borderRadius: '999px', fontSize: '0.8rem' }}>{pack.pack_health}</span>
                </div>
                <p style={{ color: '#94a3b8' }}>{pack.description}</p>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '16px' }}>
                  <div>
                    <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>Version</div>
                    <div>{pack.version}</div>
                  </div>
                  <div>
                    <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>Average Score</div>
                    <div>{pack.average_score}</div>
                  </div>
                  <div>
                    <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>Pack Coverage</div>
                    <div>{pack.validation.detection_count} detections</div>
                  </div>
                  <div>
                    <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>Validation Status</div>
                    <div>{pack.validation.manifest_valid && pack.validation.detections_valid ? 'Pass' : 'Needs review'}</div>
                  </div>
                </div>
                <div style={{ marginTop: '14px' }}>
                  <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>Focus Areas</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '8px' }}>
                    {pack.focus_areas.map((focus) => (
                      <span key={focus} style={{ background: '#111827', border: '1px solid #334155', padding: '4px 10px', borderRadius: '999px', fontSize: '0.8rem' }}>
                        {focus}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section id="reports" style={{ marginTop: '36px', marginBottom: '32px' }}>
          <h2 style={{ fontSize: '2rem' }}>Reports</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '16px' }}>
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px' }}>
              <h3 style={{ marginTop: 0 }}>Coverage by Platform</h3>
              <div style={{ width: '100%', height: 280 }}>
                <ResponsiveContainer>
                  <BarChart data={platformData}>
                    <CartesianGrid stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="name" stroke="#cbd5e1" />
                    <YAxis stroke="#cbd5e1" allowDecimals={false} />
                    <Tooltip />
                    <Bar dataKey="value" fill="#22c55e" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px' }}>
              <h3 style={{ marginTop: 0 }}>Validation & Weak Detections</h3>
              <p style={{ color: '#94a3b8' }}>Library health: {dashboard?.reports.valid ? 'passing validation' : 'validation issues detected'}.</p>
              <ul>
                {(dashboard?.reports.weak_detections ?? []).map((item) => (
                  <li key={item.id + item.title}>{item.title} ({item.score}/100)</li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      </section>
    </main>
  )
}
