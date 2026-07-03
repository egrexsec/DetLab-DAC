import Link from 'next/link'
import { contentLanes } from '../../data/site-content.mjs'

export default function ContentLandingPage() {
  const detectionLane = contentLanes[0]

  return (
    <main style={{ minHeight: '100vh', padding: '40px 24px 80px', background: '#020617', color: '#e2e8f0' }}>
      <div style={{ maxWidth: '1100px', margin: '0 auto', display: 'grid', gap: '24px' }}>
        <div style={{ display: 'grid', gap: '10px' }}>
          <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
            DetLab-DAC Content
          </div>
          <h1 style={{ margin: 0 }}>Detection engineering lane</h1>
          <p style={{ color: '#94a3b8', margin: 0, lineHeight: 1.7 }}>
            DetLab now exposes one focused lane. Open it to review the packaging model, inspect example entries, and draft a detection brief that documents Sigma, SPL, KQL, EQL, ES|QL, and related implementations in one artifact.
          </p>
        </div>

        <Link
          href={`/content/${detectionLane.slug}`}
          style={{
            background: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: '18px',
            padding: '20px',
            color: '#e2e8f0',
            textDecoration: 'none',
            display: 'grid',
            gap: '12px',
          }}
        >
          <div style={{ color: '#38bdf8', fontWeight: 800, textTransform: 'uppercase', fontSize: '0.8rem', letterSpacing: '0.12em' }}>
            {detectionLane.shortTitle}
          </div>
          <h2 style={{ margin: 0 }}>{detectionLane.title}</h2>
          <p style={{ margin: 0, color: '#94a3b8', lineHeight: 1.6 }}>{detectionLane.description}</p>
          <div style={{ color: '#cbd5e1', fontSize: '0.92rem' }}>
            <strong>Repository area:</strong> {detectionLane.repositoryArea}
          </div>
        </Link>
      </div>
    </main>
  )
}
