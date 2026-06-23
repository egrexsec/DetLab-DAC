export const capabilityPillars = [
  {
    title: 'Detection engineering',
    description: 'Document high-signal detections, map them to ATT&CK, and explain where they fit in a defender workflow.',
  },
  {
    title: 'Threat hunting',
    description: 'Capture hypotheses, pivots, telemetry assumptions, and the next detections a hunt should produce.',
  },
  {
    title: 'Investigations and DFIR',
    description: 'Turn incident notes, case studies, and forensic writeups into durable public-facing knowledge.',
  },
  {
    title: 'Learning paths and labs',
    description: 'Package study tracks, lab notes, and practice environments into portfolio-ready learning artifacts.',
  },
]

export const roadmap = [
  'Keep DetLab focused on being a polished website-only product, not a mixed website-plus-backend product.',
  'Expand the site content and visual identity so each security lane feels like a real documentation surface.',
  'Later, extract the best patterns into a self-hostable template that other practitioners can spin up for their own portfolio or team knowledge base.',
]

export const contentLanes = [
  {
    slug: 'detections',
    title: 'Detection Engineering',
    shortTitle: 'Detections',
    description: 'A website lane for publishing defender-focused detections with context, logic, and follow-on investigation guidance.',
    audience: 'Detection engineers, SOC analysts, and security engineers',
    repositoryArea: 'detections/ and knowledge/detection-engineering/',
    futureTemplateNote: 'This lane is intended to become a reusable starter pattern for teams that want a documentation-first detection catalog.',
    highlights: ['ATT&CK-mapped writeups', 'platform-specific detections', 'clear investigation follow-through'],
    entries: [
      {
        title: 'Encoded PowerShell detection notes',
        summary: 'A detection-focused article shape for malicious PowerShell execution and the telemetry needed to support it.',
        tags: ['windows', 'execution', 'ATT&CK'],
      },
      {
        title: 'Rundll32 abuse coverage',
        summary: 'A detection story for LOLBIN execution, expected false positives, and escalation paths.',
        tags: ['windows', 'lolbins', 'triage'],
      },
    ],
  },
  {
    slug: 'threat-hunts',
    title: 'Threat Hunts',
    shortTitle: 'Threat Hunts',
    description: 'A lane for hypothesis-driven hunt writeups, pivot ideas, supporting telemetry, and downstream detection opportunities.',
    audience: 'Threat hunters and blue-team operators',
    repositoryArea: 'knowledge/threat-hunts/',
    futureTemplateNote: 'This lane is designed so future users could fork the repo and publish their own hunt library with a reusable template-friendly starter structure.',
    highlights: ['hunt hypotheses', 'pivot paths', 'follow-on detection ideas'],
    entries: [
      {
        title: 'Rare IAM user activity hunt',
        summary: 'A hunt format for suspicious identity behavior, investigation questions, and escalation logic.',
        tags: ['aws', 'identity', 'hunt'],
      },
      {
        title: 'Endpoint execution anomaly hunt',
        summary: 'A site entry type for surfacing unusual execution paths before turning them into formal detections.',
        tags: ['endpoint', 'telemetry', 'behavior'],
      },
    ],
  },
  {
    slug: 'investigations',
    title: 'Investigations and DFIR',
    shortTitle: 'Investigations',
    description: 'A lane for incident response stories, cloud case studies, forensic notes, and response-oriented writeups.',
    audience: 'Incident responders, DFIR analysts, and security engineers',
    repositoryArea: 'knowledge/incident-response-case-studies/, knowledge/flaws-cloud/, and knowledge/flaws2-cloud/',
    futureTemplateNote: 'This lane should eventually stand on its own as a reusable incident-writeup website template.',
    highlights: ['case-study format', 'timeline-ready notes', 'response lessons learned'],
    entries: [
      {
        title: 'Cloud privilege escalation case-study pattern',
        summary: 'A publication format for showing what happened, how it was investigated, and what defenders should change next.',
        tags: ['cloud', 'incident-response', 'case-study'],
      },
      {
        title: 'Forensic artifact writeup structure',
        summary: 'A lane for artifact-centered writeups with evidence, interpretation, and recommended follow-up.',
        tags: ['dfir', 'forensics', 'artifacts'],
      },
    ],
  },
  {
    slug: 'learning-paths',
    title: 'Learning Paths and Labs',
    shortTitle: 'Learning Paths',
    description: 'A lane for study tracks, structured labs, and security learning notes that can be published like real portfolio content.',
    audience: 'Learners, practitioners building portfolios, and teams documenting internal learning tracks',
    repositoryArea: 'knowledge/learning-paths/, knowledge/aws-security-learning/, and knowledge/labs/',
    futureTemplateNote: 'This lane is a strong candidate for the eventual self-hostable starter because it maps cleanly to public portfolio and internal enablement use cases.',
    highlights: ['study tracks', 'lab notes', 'portfolio-ready documentation'],
    entries: [
      {
        title: 'AWS security learning track',
        summary: 'A website section for chaining concepts, labs, and references into one coherent study path.',
        tags: ['aws', 'learning', 'curriculum'],
      },
      {
        title: 'Hands-on lab publish flow',
        summary: 'A lane for turning raw lab notes into durable public artifacts instead of private scratch files.',
        tags: ['labs', 'portfolio', 'documentation'],
      },
    ],
  },
]

export function getLaneBySlug(slug) {
  return contentLanes.find((lane) => lane.slug === slug) ?? null
}
