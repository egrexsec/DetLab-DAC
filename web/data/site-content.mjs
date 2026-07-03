export const capabilityPillars = [
  {
    title: 'Canonical detections',
    description: 'Keep executable or near-executable detection logic in repo-backed files under detections/, separated cleanly from surrounding narrative.',
  },
  {
    title: 'Multi-language coverage',
    description: 'Document one detection across Sigma, SPL, KQL, EQL, ES|QL, and other dialects without losing intent or telemetry assumptions.',
  },
  {
    title: 'Triage and validation',
    description: 'Capture false positives, analyst triage, and validation notes so the detection is usable, not just syntactically present.',
  },
  {
    title: 'Pack-friendly publishing',
    description: 'Package detections into themed bundles and supporting docs that are easy to publish, review, and reuse.',
  },
]

export const roadmap = [
  'Keep DetLab static-host friendly while making the authoring flow strong for documentation-first detection engineering.',
  'Use one focused detection workbench instead of splitting attention across hunts, investigations, labs, and unrelated security content.',
  'Improve side-by-side translation and documentation of detections across Sigma, SPL, KQL, EQL, ES|QL, and other platform dialects.',
]

export const contentLanes = [
  {
    slug: 'detections',
    title: 'Detection Engineering',
    shortTitle: 'Detections',
    description: 'A single lane for documenting detection logic, telemetry assumptions, ATT&CK mapping, triage guidance, validation notes, and parallel query-language implementations.',
    audience: 'Detection engineers, SOC analysts, and security engineers',
    repositoryArea: 'detections/, knowledge/detection-engineering/, and examples/packs/',
    futureTemplateNote: 'This lane is intentionally narrow so the repo can evolve into a reusable detection-documentation starter for teams that need one canonical place to explain and compare detection logic.',
    highlights: ['Sigma to platform translations', 'ATT&CK plus telemetry context', 'triage and validation guidance'],
    entries: [
      {
        title: 'Encoded PowerShell detection brief',
        summary: 'One documented detection with Sigma, SPL, KQL, and Elastic-oriented implementations mapped back to the same behavior.',
        tags: ['windows', 'powershell', 'sigma', 'kql'],
      },
      {
        title: 'AWS access-key persistence coverage',
        summary: 'A cloud detection brief that keeps the ATT&CK story, telemetry assumptions, and query translations together.',
        tags: ['aws', 'cloudtrail', 'spl', 'eql'],
      },
      {
        title: 'Rundll32 abuse detection pack note',
        summary: 'A pack-ready documentation shape for platform-specific detections with false positives and validation guidance.',
        tags: ['windows', 'lolbins', 'esql', 'triage'],
      },
    ],
  },
]

export function getLaneBySlug(slug) {
  return contentLanes.find((lane) => lane.slug === slug) ?? null
}
