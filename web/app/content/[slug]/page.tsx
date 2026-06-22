import { notFound } from 'next/navigation'
import ContentIndexPage from '../../../components/content-index-page'
import { CONTENT_INDEX_DEFINITIONS } from '../../../config/content-indexes.mjs'

export function generateStaticParams() {
  return CONTENT_INDEX_DEFINITIONS.map((entry) => ({ slug: entry.slug }))
}

export default function ContentIndexRoute({ params }: { params: { slug: string } }) {
  const known = CONTENT_INDEX_DEFINITIONS.some((entry) => entry.slug === params.slug)
  if (!known) {
    notFound()
  }

  return <ContentIndexPage slug={params.slug} />
}
