import Link from 'next/link'
import { getContentIndexNavigation } from '../../config/content-indexes.mjs'

export default function ContentLandingPage() {
  const navigation = getContentIndexNavigation()

  return (
    <main style={{ minHeight: '100vh', background: '#020617', color: '#e2e8f0', padding: '32px' }}>
      <div style={{ maxWidth: '1000px', margin: '0 auto', display: 'grid', gap: '20px' }}>
        <div>
          <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>DetLab Content</div>
          <h1 style={{ marginBottom: '8px' }}>Knowledge Indexes</h1>
          <p style={{ color: '#94a3b8', margin: 0 }}>Browse the DetLab knowledge library by artifact type: hunts, investigations, forensic writeups, and learning paths.</p>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '16px' }}>
          {navigation.map((entry) => (
            <Link key={entry.slug} href={entry.href} style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px', color: '#e2e8f0', textDecoration: 'none' }}>
              <h2 style={{ marginTop: 0 }}>{entry.title}</h2>
              <p style={{ color: '#94a3b8', marginBottom: 0 }}>{entry.description}</p>
            </Link>
          ))}
        </div>
      </div>
    </main>
  )
}
