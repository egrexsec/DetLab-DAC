'use client'

import { useEffect, useState } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
} from 'recharts'

type DashboardSummary = {
  total_detections: number
  behavioral_sequences: number
  average_score: number
}

type Distribution = Record<string, number>

type DashboardData = {
  summary: DashboardSummary
  tactics: Distribution
  severity: Distribution
  status: Distribution
  maturity: Distribution
}

type ChartDatum = {
  name: string
  value: number
}

const COLORS = ['#2563eb', '#16a34a', '#f59e0b', '#dc2626']

const ATTACK_TACTICS = [
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
]

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? '/api'

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

  const severityData: ChartDatum[] = dashboard
    ? Object.entries(dashboard.severity).map(([name, value]) => ({ name, value }))
    : []

  const maturityData: ChartDatum[] = dashboard
    ? Object.entries(dashboard.maturity).map(([name, value]) => ({ name, value }))
    : []

  const tacticData = dashboard?.tactics ?? {}

  function tacticColor(value: number) {
    if (value >= 10) return '#dc2626'
    if (value >= 5) return '#f59e0b'
    if (value >= 1) return '#16a34a'
    return '#334155'
  }

  return (
    <main
      style={{
        padding: '2rem',
        fontFamily: 'Arial',
        background: '#0f172a',
        minHeight: '100vh',
        color: 'white',
      }}
    >
      <h1 style={{ fontSize: '2.5rem' }}>DetLab Dashboard</h1>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '1rem',
          marginTop: '2rem',
        }}
      >
        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '12px' }}>
          <h2>Total Detections</h2>
          <p style={{ fontSize: '2rem' }}>{dashboard?.summary?.total_detections ?? 0}</p>
        </div>

        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '12px' }}>
          <h2>Behavioral Sequences</h2>
          <p style={{ fontSize: '2rem' }}>{dashboard?.summary?.behavioral_sequences ?? 0}</p>
        </div>

        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '12px' }}>
          <h2>Average Score</h2>
          <p style={{ fontSize: '2rem' }}>{dashboard?.summary?.average_score ?? 0}</p>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '2rem',
          marginTop: '3rem',
        }}
      >
        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '12px' }}>
          <h2>Severity Distribution</h2>

          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={severityData}>
              <XAxis dataKey="name" stroke="#ffffff" />
              <YAxis stroke="#ffffff" />
              <Tooltip />
              <Bar dataKey="value" fill="#2563eb" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '12px' }}>
          <h2>Maturity Distribution</h2>

          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={maturityData}
                dataKey="value"
                nameKey="name"
                outerRadius={100}
                label
              >
                {maturityData.map((entry, index) => (
                  <Cell key={`${entry.name}-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>

              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div
        style={{
          marginTop: '3rem',
          background: '#1e293b',
          padding: '1.5rem',
          borderRadius: '12px',
        }}
      >
        <h2>ATT&CK Coverage Heatmap</h2>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(5, 1fr)',
            gap: '1rem',
            marginTop: '1.5rem',
          }}
        >
          {ATTACK_TACTICS.map((tactic) => {
            const value = tacticData[tactic] ?? 0

            return (
              <div
                key={tactic}
                style={{
                  background: tacticColor(value),
                  padding: '1rem',
                  borderRadius: '10px',
                  minHeight: '90px',
                }}
              >
                <h3 style={{ fontSize: '0.95rem' }}>{tactic}</h3>
                <p style={{ fontSize: '2rem', marginTop: '0.5rem' }}>{value}</p>
              </div>
            )
          })}
        </div>
      </div>
    </main>
  )
}
