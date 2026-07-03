const DEFAULT_REPO_OWNER = 'egrexsec'
const DEFAULT_REPO_NAME = 'DetLab-DAC'
const DEFAULT_BRANCH = 'main'

export const laneWorkbenchConfigs = {
  detections: {
    laneSlug: 'detections',
    label: 'Detection workbench',
    artifactType: 'Detection documentation markdown',
    fileExtension: '.md',
    repositoryDefaults: {
      owner: DEFAULT_REPO_OWNER,
      repo: DEFAULT_REPO_NAME,
      branch: DEFAULT_BRANCH,
      directory: 'knowledge/detection-engineering',
    },
    defaults: {
      sigma: `title: Suspicious Encoded PowerShell\nid: det-encoded-powershell\nstatus: experimental\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n    CommandLine|contains:\n      - '-enc'\n  condition: selection`,
      spl: `index=win* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational Image="*\\powershell.exe" CommandLine="*-enc*"`,
      kql: `DeviceProcessEvents\n| where FileName =~ "powershell.exe"\n| where ProcessCommandLine has "-enc"`,
      eql: `process where host.os.type == "windows" and process.name == "powershell.exe" and process.command_line like "*-enc*"`,
      esql: `from logs-endpoint.events.process-*\n| where process.name == "powershell.exe"\n| where process.command_line like "%-enc%"`,
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

export function normalizeLines(value) {
  return value
    .split('\n')
    .map((item) => item.trim())
    .filter(Boolean)
}

export function buildRepoFilePath(directory, filename) {
  return `${directory.replace(/\/$/, '')}/${filename.replace(/^\//, '')}`
}

function formatFrontmatterList(items) {
  if (!items.length) {
    return '[]'
  }

  return `[${items.map((item) => `'${item.replace(/'/g, "''")}'`).join(', ')}]`
}

function renderBulletSection(title, items, fallback) {
  const normalizedItems = Array.isArray(items) ? items.filter(Boolean) : []

  if (!normalizedItems.length) {
    return `## ${title}\n- ${fallback}`
  }

  return `## ${title}\n${normalizedItems.map((item) => `- ${item}`).join('\n')}`
}

export function buildLaneArtifact({
  laneSlug,
  title,
  summary,
  tags,
  author,
  technique,
  tactic,
  severity,
  status,
  platform,
  telemetry,
  sigma,
  spl,
  kql,
  eql,
  esql,
  otherLanguage,
  otherQuery,
  triage,
  validation,
  falsePositives,
  references,
}) {
  const config = getWorkbenchConfig(laneSlug)

  if (!config) {
    throw new Error(`Unsupported workbench lane: ${laneSlug}`)
  }

  const safeTitle = title.trim()
  const slug = slugify(safeTitle || laneSlug)
  const normalizedTags = normalizeTags(tags || '')
  const effectiveAuthor = author?.trim() || 'mell0wx'
  const referenceLines = normalizeLines(references || '')
  const triageLines = normalizeLines(triage || '')
  const validationLines = normalizeLines(validation || '')
  const falsePositiveLines = normalizeLines(falsePositives || '')
  const safeOtherLanguage = otherLanguage?.trim() || 'Other'

  const fence = '```'
  const codeSection = (title, language, body, fallback) =>
    `## ${title}\n\n${fence}${language}\n${body.trim() || fallback}\n${fence}`

  const sections = [
    '---',
    `title: ${safeTitle || 'New detection brief'}`,
    `detection_id: ${slug ? `DET-${slug.toUpperCase().replace(/-/g, '_')}` : 'DET-NEW'}`,
    `author: ${effectiveAuthor}`,
    `status: ${status.trim() || 'draft'}`,
    `severity: ${severity.trim() || 'medium'}`,
    `platform: ${platform.trim() || 'windows'}`,
    `tags: ${formatFrontmatterList(normalizedTags)}`,
    `attack_tactic: ${tactic.trim() || 'execution'}`,
    `attack_technique: ${technique.trim() || 'TBD'}`,
    '---',
    '',
    '## Summary',
    summary.trim() || 'Describe what the detection finds, why it matters, and where it is expected to fire.',
    '',
    '## Telemetry and prerequisites',
    telemetry.trim() || 'Document the telemetry sources, field requirements, retention assumptions, and parser dependencies needed to run this detection reliably.',
    '',
    codeSection('Sigma', 'yaml', sigma, config.defaults.sigma),
    '',
    codeSection('Splunk SPL', 'spl', spl, config.defaults.spl),
    '',
    codeSection('Microsoft Sentinel KQL', 'kusto', kql, config.defaults.kql),
    '',
    codeSection('Elastic EQL', 'eql', eql, config.defaults.eql),
    '',
    codeSection('Elastic ES|QL', 'esql', esql, config.defaults.esql),
  ]

  if ((otherLanguage || '').trim() || (otherQuery || '').trim()) {
    sections.push('', codeSection(safeOtherLanguage, '', otherQuery, 'Add an additional platform-specific implementation.'))
  }

  sections.push(
    '',
    renderBulletSection('False positives', falsePositiveLines, 'Document expected benign explanations and environmental edge cases.'),
    '',
    renderBulletSection('Triage guidance', triageLines, 'Add the first checks an analyst should perform when this detection fires.'),
    '',
    renderBulletSection('Validation notes', validationLines, 'Explain how this detection was tested or how it should be validated before production use.'),
    '',
    renderBulletSection('References', referenceLines, 'Add ATT&CK, vendor, or research references.'),
    ''
  )

  return {
    filename: `${slug || 'new-detection-brief'}${config.fileExtension}`,
    commitMessage: `Add detection brief: ${safeTitle || 'new detection brief'}`,
    content: sections.join('\n'),
  }
}
