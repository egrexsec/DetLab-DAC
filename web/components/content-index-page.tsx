'use client'

import Link from 'next/link'
import { useEffect, useMemo, useState } from 'react'
import { buildContentIndexCards, buildWorkbenchEditHref, getContentIndexDefinition, getContentIndexNavigation } from '../config/content-indexes.mjs'

type ContentItem = {
  id: string
  name: string
  title: string
  description: string
  severity: string
  status: string
  content_kind: string
  path: string
  domain: string[]
  platforms: string[]
  attack_techniques: string[]
}

type ContentIndexCard = {
  key: string
  slug: string
  title: string
  description: string
  emptyState: string
  href: string
  count: number
  items: ContentItem[]
}

type ContentIndexesPayload = {
  total: number
  indexes: Record<string, { count: number; items: ContentItem[] }>
}

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? '/api'

export default function ContentIndexPage({ slug }: { slug: string }) {
  const [payload, setPayload] = useState<ContentIndexesPayload | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const cards = useMemo(() => buildContentIndexCards(payload), [payload]) as ContentIndexCard[]
  const current = useMemo(() => cards.find((card) => card.slug === slug) ?? null, [cards, slug])
  const navigation = useMemo(() => getContentIndexNavigation(), [])
  const definition = useMemo(() => getContentIndexDefinition(slug), [slug])

  useEffect(() => {
    async function load() {
      setLoading(true)
      setError(null)
      try {
        const response = await fetch(`${API_BASE_URL}/content/indexes`)
        const body = await response.json()
        if (!response.ok) {
          throw new Error(body?.detail || `content index request failed: ${response.status}`)
        }
        setPayload(body)
      } catch {
        setPayload(null)
        setError('The content index could not be loaded. Check that the FastAPI service is reachable and retry.')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [])

  if (!definition) {
    return (
      <main style={{ minHeight: '100vh', background: '#020617', color: '#e2e8f0', padding: '32px' }}>
        <h1>Unknown content index</h1>
        <p>That content route is not defined.</p>
      </main>
    )
  }

  return (
    <main style={{ minHeight: '100vh', background: '#020617', color: '#e2e8f0', padding: '32px' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'grid', gap: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div>
            <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>DetLab Content</div>
            <h1 style={{ marginBottom: '8px' }}>{definition.title}</h1>
            <p style={{ color: '#94a3b8', margin: 0 }}>{definition.description}</p>
          </div>
          <Link href="/" style={{ color: '#e2e8f0', textDecoration: 'none', border: '1px solid #334155', borderRadius: '999px', padding: '10px 14px' }}>
            Back to workspace
          </Link>
        </div>

        <nav style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {navigation.map((entry) => {
            const active = entry.slug === slug
            return (
              <Link
                key={entry.slug}
                href={entry.href}
                style={{
                  background: active ? '#0f172a' : '#111827',
                  color: active ? '#e0f2fe' : '#cbd5e1',
                  border: active ? '1px solid #38bdf8' : '1px solid #334155',
                  borderRadius: '999px',
                  padding: '10px 14px',
                  textDecoration: 'none',
                }}
              >
                {entry.title}
              </Link>
            )
          })}
        </nav>

        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '20px' }}>
          {loading ? <div>Loading content index…</div> : null}
          {error ? <div style={{ color: '#fca5a5' }}>{error}</div> : null}
          {!loading && !error && current ? (
            <div style={{ display: 'grid', gap: '16px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '12px' }}>
                <Stat label="Indexed Items" value={String(current.count)} />
                <Stat label="Route" value={current.href} />
                <Stat label="Knowledge Scope" value="knowledge/" />
              </div>
              {current.items.length ? (
                <div style={{ display: 'grid', gap: '12px' }}>
                  {current.items.map((item) => (
                    <article key={item.id} style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '16px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
                        <div>
                          <div style={{ color: '#38bdf8', fontSize: '0.8rem', fontWeight: 700 }}>{item.id}</div>
                          <h2 style={{ margin: '6px 0 6px', fontSize: '1.15rem' }}>{item.name}</h2>
                        </div>
                        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                          <Tag label={item.content_kind} />
                          <Tag label={item.status} />
                          <Tag label={item.severity} />
                        </div>
                      </div>
                      <p style={{ color: '#94a3b8', marginTop: '8px' }}>{item.description}</p>
                      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '12px' }}>
                        {item.domain.map((value) => <Tag key={`${item.id}-domain-${value}`} label={value} />)}
                        {item.platforms.map((value) => <Tag key={`${item.id}-platform-${value}`} label={value} />)}
                        {item.attack_techniques.map((value) => <Tag key={`${item.id}-attack-${value}`} label={value} />)}
                      </div>
                      <div style={{ marginTop: '12px', color: '#cbd5e1', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace', fontSize: '0.88rem' }}>
                        {item.path}
                      </div>
                      <div style={{ marginTop: '14px', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                        <Link
                          href={buildWorkbenchEditHref(item)}
                          style={{ background: '#1d4ed8', color: '#dbeafe', border: '1px solid #2563eb', borderRadius: '10px', padding: '9px 12px', textDecoration: 'none', fontWeight: 700, fontSize: '0.88rem' }}
                        >
                          Edit in workbench
                        </Link>
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <div style={{ color: '#94a3b8' }}>{current.emptyState}</div>
              )}
            </div>
          ) : null}
        </div>
      </div>
    </main>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '12px', padding: '12px' }}>
      <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>{label}</div>
      <div style={{ marginTop: '6px', fontWeight: 700 }}>{value}</div>
    </div>
  )
}

function Tag({ label }: { label: string }) {
  return <span style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '999px', padding: '6px 10px', fontSize: '0.8rem' }}>{label}</span>
}
