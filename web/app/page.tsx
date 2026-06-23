import Link from 'next/link'
import { capabilityPillars, contentLanes, roadmap } from '../data/site-content.mjs'

const shellStyle = {
  minHeight: '100vh',
  padding: '40px 24px 80px',
  background:
    'radial-gradient(circle at top, rgba(14,165,233,0.18), transparent 28%), linear-gradient(180deg, #020617 0%, #0f172a 100%)',
} as const

const cardStyle = {
  background: 'rgba(15, 23, 42, 0.9)',
  border: '1px solid #1e293b',
  borderRadius: '20px',
  padding: '20px',
  boxShadow: '0 16px 40px rgba(2, 6, 23, 0.28)',
} as const

export default function HomePage() {
  return (
    <main style={shellStyle}>
      <div style={{ maxWidth: '1160px', margin: '0 auto', display: 'grid', gap: '28px' }}>
        <section style={{ ...cardStyle, padding: '32px', display: 'grid', gap: '18px' }}>
          <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.18em', fontSize: '12px', fontWeight: 800 }}>
            DetLab
          </div>
          <div style={{ display: 'grid', gap: '14px', maxWidth: '860px' }}>
            <h1 style={{ margin: 0, fontSize: 'clamp(2.5rem, 6vw, 4.4rem)', lineHeight: 1.02 }}>
              A website-only home for serious security documentation.
            </h1>
            <p style={{ margin: 0, color: '#cbd5e1', fontSize: '1.1rem', lineHeight: 1.7 }}>
              DetLab is no longer positioned as a hybrid app with a backend workbench. The product direction is a focused website for publishing
              detections, threat hunts, investigations, DFIR notes, and learning paths in a portfolio-quality format.
            </p>
            <p style={{ margin: 0, color: '#94a3b8', fontSize: '1rem', lineHeight: 1.7 }}>
              Longer term, the strongest patterns here can be turned into a self-hostable template that other practitioners or teams can spin up
              for their own security knowledge base.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <Link
              href="/content"
              style={{
                background: '#0f766e',
                color: '#ccfbf1',
                border: '1px solid #14b8a6',
                borderRadius: '999px',
                padding: '12px 18px',
                textDecoration: 'none',
                fontWeight: 800,
              }}
            >
              Browse content lanes
            </Link>
            <a
              href="https://github.com/egrexsec/DetLab-DAC"
              style={{
                color: '#e2e8f0',
                border: '1px solid #334155',
                borderRadius: '999px',
                padding: '12px 18px',
                textDecoration: 'none',
                fontWeight: 700,
              }}
            >
              View repository
            </a>
          </div>
        </section>

        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
          {capabilityPillars.map((pillar) => (
            <article key={pillar.title} style={cardStyle}>
              <h2 style={{ marginTop: 0, marginBottom: '10px', fontSize: '1.1rem' }}>{pillar.title}</h2>
              <p style={{ margin: 0, color: '#94a3b8', lineHeight: 1.6 }}>{pillar.description}</p>
            </article>
          ))}
        </section>

        <section style={{ ...cardStyle, display: 'grid', gap: '18px' }}>
          <div>
            <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
              Content architecture
            </div>
            <h2 style={{ marginBottom: '8px' }}>Four website lanes, one documentation standard</h2>
            <p style={{ color: '#94a3b8', margin: 0, lineHeight: 1.7 }}>
              Each lane exists to make the site legible to a hiring manager, peer defender, or future template user within a quick scan.
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
            {contentLanes.map((lane) => (
              <Link
                key={lane.slug}
                href={`/content/${lane.slug}`}
                style={{
                  ...cardStyle,
                  background: '#111827',
                  color: '#e2e8f0',
                  textDecoration: 'none',
                  display: 'grid',
                  gap: '10px',
                }}
              >
                <div style={{ color: '#38bdf8', fontWeight: 800, textTransform: 'uppercase', fontSize: '0.78rem', letterSpacing: '0.12em' }}>
                  {lane.shortTitle}
                </div>
                <h3 style={{ margin: 0 }}>{lane.title}</h3>
                <p style={{ margin: 0, color: '#94a3b8', lineHeight: 1.6 }}>{lane.description}</p>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {lane.highlights.map((item) => (
                    <span
                      key={`${lane.slug}-${item}`}
                      style={{
                        background: '#0f172a',
                        border: '1px solid #334155',
                        borderRadius: '999px',
                        padding: '6px 10px',
                        fontSize: '0.78rem',
                        color: '#cbd5e1',
                      }}
                    >
                      {item}
                    </span>
                  ))}
                </div>
              </Link>
            ))}
          </div>
        </section>

        <section style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.25fr) minmax(280px, 0.75fr)', gap: '16px' }}>
          <article style={cardStyle}>
            <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
              Repository direction
            </div>
            <h2 style={{ marginBottom: '10px' }}>Website-only now, template-ready later</h2>
            <ul style={{ margin: 0, paddingLeft: '18px', color: '#cbd5e1', lineHeight: 1.8 }}>
              {roadmap.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </article>
          <article style={cardStyle}>
            <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
              Local run
            </div>
            <h2 style={{ marginBottom: '10px' }}>Simple website workflow</h2>
            <pre
              style={{
                margin: 0,
                whiteSpace: 'pre-wrap',
                background: '#020617',
                border: '1px solid #1e293b',
                borderRadius: '14px',
                padding: '16px',
                color: '#cbd5e1',
                lineHeight: 1.6,
                fontSize: '0.92rem',
              }}
            >{`cd web
npm install
npm run dev`}</pre>
          </article>
        </section>
      </div>
    </main>
  )
}
