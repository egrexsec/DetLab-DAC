import Link from 'next/link'
import { notFound } from 'next/navigation'
import { contentLanes, getLaneBySlug } from '../../../data/site-content.mjs'

export function generateStaticParams() {
  return contentLanes.map((lane) => ({ slug: lane.slug }))
}

export default function ContentLanePage({ params }: { params: { slug: string } }) {
  const lane = getLaneBySlug(params.slug)

  if (!lane) {
    notFound()
  }

  return (
    <main style={{ minHeight: '100vh', padding: '40px 24px 80px', background: '#020617', color: '#e2e8f0' }}>
      <div style={{ maxWidth: '1080px', margin: '0 auto', display: 'grid', gap: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ display: 'grid', gap: '8px', maxWidth: '760px' }}>
            <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
              {lane.shortTitle}
            </div>
            <h1 style={{ margin: 0 }}>{lane.title}</h1>
            <p style={{ color: '#94a3b8', margin: 0, lineHeight: 1.7 }}>{lane.description}</p>
          </div>
          <Link
            href="/content"
            style={{ color: '#e2e8f0', textDecoration: 'none', border: '1px solid #334155', borderRadius: '999px', padding: '10px 14px' }}
          >
            Back to lanes
          </Link>
        </div>

        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
          <StatCard label="Audience" value={lane.audience} />
          <StatCard label="Repository area" value={lane.repositoryArea} />
          <StatCard label="Template direction" value="Future self-hostable starter" />
        </section>

        <section style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.2fr) minmax(280px, 0.8fr)', gap: '16px' }}>
          <article style={cardStyle}>
            <h2 style={{ marginTop: 0 }}>What belongs here</h2>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '12px' }}>
              {lane.highlights.map((item) => (
                <span key={`${lane.slug}-${item}`} style={tagStyle}>
                  {item}
                </span>
              ))}
            </div>
            <p style={{ color: '#94a3b8', lineHeight: 1.7, marginBottom: 0 }}>{lane.futureTemplateNote}</p>
          </article>
          <article style={cardStyle}>
            <h2 style={{ marginTop: 0 }}>Publishing standard</h2>
            <ul style={{ margin: 0, paddingLeft: '18px', color: '#cbd5e1', lineHeight: 1.8 }}>
              <li>Explain what happened and why it matters.</li>
              <li>Show the defender workflow, not just the headline idea.</li>
              <li>Keep each entry legible enough for hiring, portfolio, and peer-review use.</li>
            </ul>
          </article>
        </section>

        <section style={cardStyle}>
          <h2 style={{ marginTop: 0 }}>Example entries for this lane</h2>
          <div style={{ display: 'grid', gap: '14px' }}>
            {lane.entries.map((entry) => (
              <article key={`${lane.slug}-${entry.title}`} style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '16px' }}>
                <h3 style={{ marginTop: 0, marginBottom: '8px' }}>{entry.title}</h3>
                <p style={{ color: '#94a3b8', marginTop: 0, lineHeight: 1.6 }}>{entry.summary}</p>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {entry.tags.map((tag) => (
                    <span key={`${entry.title}-${tag}`} style={tagStyle}>
                      {tag}
                    </span>
                  ))}
                </div>
              </article>
            ))}
          </div>
        </section>
      </div>
    </main>
  )
}

const cardStyle = {
  background: '#0f172a',
  border: '1px solid #1e293b',
  borderRadius: '18px',
  padding: '20px',
} as const

const tagStyle = {
  background: '#020617',
  border: '1px solid #334155',
  borderRadius: '999px',
  padding: '6px 10px',
  fontSize: '0.8rem',
  color: '#cbd5e1',
} as const

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '16px' }}>
      <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginBottom: '6px' }}>{label}</div>
      <div style={{ fontWeight: 700, lineHeight: 1.5 }}>{value}</div>
    </div>
  )
}
