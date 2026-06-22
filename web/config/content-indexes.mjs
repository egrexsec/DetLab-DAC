export const CONTENT_INDEX_DEFINITIONS = [
  {
    key: 'hunts',
    slug: 'threat-hunts',
    title: 'Threat Hunts',
    description: 'Hypothesis-driven hunts, pivots, and follow-on detection opportunities.',
    emptyState: 'No threat hunts are indexed yet. Save a hunt into knowledge/threat-hunts/ to populate this page.',
  },
  {
    key: 'investigations',
    slug: 'investigations',
    title: 'Investigations',
    description: 'Incident response writeups, case studies, and investigation narratives.',
    emptyState: 'No investigations are indexed yet. Save an incident response or investigation artifact into knowledge/.',
  },
  {
    key: 'forensics',
    slug: 'forensic-writeups',
    title: 'Forensic Writeups',
    description: 'Artifact-centric DFIR notes, timelines, and forensic summaries.',
    emptyState: 'No forensic writeups are indexed yet. Save a forensic artifact writeup into knowledge/forensics/ to populate this page.',
  },
  {
    key: 'learning_paths',
    slug: 'learning-paths',
    title: 'Learning Paths',
    description: 'Learning tracks, labs, and portfolio-ready knowledge-building artifacts.',
    emptyState: 'No learning paths are indexed yet. Save a learning path or lab into knowledge/learning-paths/ or knowledge/labs/.',
  },
]

export function getContentIndexNavigation() {
  return CONTENT_INDEX_DEFINITIONS.map((entry) => ({
    ...entry,
    href: `/content/${entry.slug}`,
  }))
}

export function buildContentIndexCards(payload) {
  return CONTENT_INDEX_DEFINITIONS.map((entry) => ({
    ...entry,
    href: `/content/${entry.slug}`,
    count: payload?.indexes?.[entry.key]?.count ?? 0,
    items: payload?.indexes?.[entry.key]?.items ?? [],
  }))
}

export function getContentIndexDefinition(slug) {
  return CONTENT_INDEX_DEFINITIONS.find((entry) => entry.slug === slug) ?? null
}
