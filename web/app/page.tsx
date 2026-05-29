'use client'

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer
} from 'recharts'

const severityData = [
  { name: 'low', value: 4 },
  { name: 'medium', value: 8 },
  { name: 'high', value: 12 },
  { name: 'critical', value: 3 }
]

const maturityData = [
  { name: 'experimental', value: 3 },
  { name: 'testing', value: 6 },
  { name: 'stable', value: 18 }
]

const COLORS = ['#2563eb', '#16a34a', '#f59e0b', '#dc2626']

export default function HomePage() {
  return (
    <main
      style={{
        padding: '2rem',
        fontFamily: 'Arial',
        background: '#0f172a',
        minHeight: '100vh',
        color: 'white'
      }}
    >
      <h1 style={{ fontSize: '2.5rem' }}>DetLab Dashboard</h1>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '1rem',
          marginTop: '2rem'
        }}
      >
        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '12px' }}>
          <h2>Total Detections</h2>
          <p style={{ fontSize: '2rem' }}>27</p>
        </div>

        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '12px' }}>
          <h2>Behavioral Sequences</h2>
          <p style={{ fontSize: '2rem' }}>8</p>
        </div>

        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '12px' }}>
          <h2>Validated Packs</h2>
          <p style={{ fontSize: '2rem' }}>5</p>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '2rem',
          marginTop: '3rem'
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
                  <Cell key={index} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>

              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </main>
  )
}
