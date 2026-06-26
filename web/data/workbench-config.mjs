const DEFAULT_REPO_OWNER = 'egrexsec'
const DEFAULT_REPO_NAME = 'DetLab-DAC'
const DEFAULT_BRANCH = 'main'

export const laneWorkbenchConfigs = {
  detections: {
    laneSlug: 'detections',
    label: 'Detection workbench',
    artifactType: 'Detection YAML',
    fileExtension: '.yml',
    bodyLabel: 'Detection logic',
    bodyPlaceholder: `detection:\n  selection:\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains:\n      - '-enc'\n  condition: selection`,
    defaultBody: `detection:\n  selection:\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains:\n      - '-enc'\n  condition: selection`,
    repositoryDefaults: {
      owner: DEFAULT_REPO_OWNER,
      repo: DEFAULT_REPO_NAME,
      branch: DEFAULT_BRANCH,
      directory: 'detections/custom',
    },
  },
  'threat-hunts': {
    laneSlug: 'threat-hunts',
    label: 'Threat hunt workbench',
    artifactType: 'Threat hunt markdown',
    fileExtension: '.md',
    bodyLabel: 'Hunt procedure',
    bodyPlaceholder: `## Hypothesis\nThe activity may indicate...\n\n## Telemetry\n- Endpoint process creation\n- Identity logs\n\n## Hunt steps\n1. Pivot on...\n2. Compare against...\n\n## Detection follow-on\n- Create a detection for...`,
    defaultBody: `## Hypothesis\nThe activity may indicate...\n\n## Telemetry\n- Endpoint process creation\n- Identity logs\n\n## Hunt steps\n1. Pivot on...\n2. Compare against...\n\n## Detection follow-on\n- Create a detection for...`,
    repositoryDefaults: {
      owner: DEFAULT_REPO_OWNER,
      repo: DEFAULT_REPO_NAME,
      branch: DEFAULT_BRANCH,
      directory: 'knowledge/threat-hunts',
    },
  },
  investigations: {
    laneSlug: 'investigations',
    label: 'Investigation workbench',
    artifactType: 'Investigation markdown',
    fileExtension: '.md',
    bodyLabel: 'Investigation notes',
    bodyPlaceholder: `## Executive summary\nDescribe what happened.\n\n## Timeline\n- Time / event\n\n## Evidence\n- Artifact\n\n## Findings\n- Key conclusion\n\n## Response and hardening\n- Action item`,
    defaultBody: `## Executive summary\nDescribe what happened.\n\n## Timeline\n- Time / event\n\n## Evidence\n- Artifact\n\n## Findings\n- Key conclusion\n\n## Response and hardening\n- Action item`,
    repositoryDefaults: {
      owner: DEFAULT_REPO_OWNER,
      repo: DEFAULT_REPO_NAME,
      branch: DEFAULT_BRANCH,
      directory: 'knowledge/incident-response-case-studies',
    },
  },
}

export const supportedWorkbenchLanes = Object.keys(laneWorkbenchConfigs)

export function getWorkbenchConfig(laneSlug) {
  return laneWorkbenchConfigs[laneSlug] ?? null
}

export function slugify(value) {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

export function normalizeTags(value) {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
}

export function buildRepoFilePath(directory, filename) {
  return `${directory.replace(/\/$/, '')}/${filename.replace(/^\//, '')}`
}

function formatYamlList(items) {
  if (!items.length) {
    return '[]'
  }

  return `\n${items.map((item) => `  - ${item}`).join('\n')}`
}

function formatFrontmatterList(items) {
  if (!items.length) {
    return '[]'
  }

  return `[${items.map((item) => `'${item.replace(/'/g, "''")}'`).join(', ')}]`
}

export function buildLaneArtifact({
  laneSlug,
  title,
  summary,
  body,
  tags,
  author,
  technique,
  tactic,
  severity,
  status,
  platform,
  hypothesis,
  scope,
}) {
  const config = getWorkbenchConfig(laneSlug)

  if (!config) {
    throw new Error(`Unsupported workbench lane: ${laneSlug}`)
  }

  const safeTitle = title.trim()
  const slug = slugify(safeTitle || laneSlug)
  const normalizedTags = normalizeTags(tags || '')
  const effectiveAuthor = author?.trim() || 'mell0wx'

  if (laneSlug === 'detections') {
    return {
      filename: `${slug || 'new-detection'}${config.fileExtension}`,
      commitMessage: `Add detection: ${safeTitle || 'new detection'}`,
      content: `id: ${slug ? `DET-${slug.toUpperCase().replace(/-/g, '_')}` : 'DET-NEW'}\ntitle: ${safeTitle || 'New detection'}\ndescription: ${summary.trim() || 'Describe what the detection finds and why it matters.'}\n\nlogsource:\n  product: ${platform.trim() || 'windows'}\n  service: process_creation\n\nattack:\n  technique: ${technique.trim() || 'TBD'}\n  tactic: ${tactic.trim() || 'execution'}\n\nseverity: ${severity.trim() || 'medium'}\nstatus: ${status.trim() || 'draft'}\nauthor: ${effectiveAuthor}\n\nreferences:${formatYamlList(normalizedTags.map((tag) => `tag:${tag}`))}\n\nfalsepositives:\n  - Add expected benign explanations\n\ntests:\n  - name: Add validation test case\n    source: manual\n    test_id: ${slug || 'new-detection'}\n\n${body.trim() || config.defaultBody}\n`,
    }
  }

  const frontmatter = [
    '---',
    `title: ${safeTitle || 'New entry'}`,
    `summary: ${summary.trim() || 'Add a short summary.'}`,
    `author: ${effectiveAuthor}`,
    `tags: ${formatFrontmatterList(normalizedTags)}`,
  ]

  if (laneSlug === 'threat-hunts') {
    frontmatter.push(`hypothesis: ${hypothesis.trim() || 'Add the hypothesis this hunt is testing.'}`)
    frontmatter.push('lane: threat-hunt')
  }

  if (laneSlug === 'investigations') {
    frontmatter.push(`scope: ${scope.trim() || 'Add the incident or investigation scope.'}`)
    frontmatter.push('lane: investigation')
  }

  frontmatter.push('---')

  return {
    filename: `${slug || 'new-entry'}${config.fileExtension}`,
    commitMessage: `Add ${laneSlug === 'threat-hunts' ? 'threat hunt' : 'investigation'}: ${safeTitle || 'new entry'}`,
    content: `${frontmatter.join('\n')}\n\n${body.trim() || config.defaultBody}\n`,
  }
}
