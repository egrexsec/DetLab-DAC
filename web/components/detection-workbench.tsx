'use client'

import { useEffect, useMemo, useState } from 'react'
import { getRepoActionDefinitions, summarizeRepoStatus } from '../config/repo-workflow.mjs'

type WorkbenchTabId = 'detection' | 'investigation' | 'hunt' | 'learning'

type ValidationErrorRow = {
  loc: Array<string | number>
  msg: string
  type: string
}

type InspectResponse = {
  valid: boolean
  errors: ValidationErrorRow[]
  source_format?: string
  normalized_from?: string
  canonical_model_version?: string
  detection?: {
    id: string
    title: string
    description: string
    severity: string
    status: string
    author: string
    attack: {
      technique: string
      tactic: string
    }
    logsource: {
      product: string
      service: string
    }
  }
  score?: {
    coverage_score: number
    specificity_score: number
    metadata_score: number
    maintainability_score: number
    false_positive_risk: number
    false_positive_risk_level: string
    overall_score: number
    recommendations: string[]
  }
}

type ConvertResponse = InspectResponse & {
  target?: string
  content?: string
}

type SaveResponse = InspectResponse & {
  saved?: boolean
  path?: string
  repo_root?: string
}

type RepoStatus = {
  branch: string
  clean: boolean
  changed_files: Array<{
    path: string
    status: string
  }>
}

type RepoDiffResponse = RepoStatus & {
  path?: string | null
  diff: string
}

type RepoCommitResponse = {
  committed: boolean
  message: string
  commit: string
  branch: string
  changed_files: Array<{
    path: string
    status: string
  }>
}

type RepoContentResponse = {
  path: string
  content: string
  content_kind: string
  name: string
}

type DetectionTemplateCatalog = {
  canonical_model_version: string
  default_format: string
  templates: Record<
    string,
    {
      label: string
      description: string
      content: string
    }
  >
}

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? '/api'
const SAMPLE_DETECTION_YAML = `id: DET-9001
title: Suspicious Encoded PowerShell
description: Detects PowerShell launched with encoded command arguments.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1059.001
  tactic: execution
severity: high
status: experimental
author: Mell0wx
domain:
  - endpoint
platforms:
  - windows
attack_context:
  - technique: T1027
    tactic: defense-evasion
    name: Obfuscated Files or Information
    coverage: partial
    rationale: Encoded commands often overlap with obfuscation tradecraft.
data_sources:
  - name: Sysmon Process Creation
    kind: endpoint
    provider: windows
    event_names:
      - Event ID 1
triage_steps:
  - step: Validate the full command line and parent process.
    priority: high
investigation_steps:
  - step: Review child processes and nearby network activity.
    priority: high
related_detections:
  - detection_id: DET-0003
    relationship: follow_on
    rationale: Encoded PowerShell often leads into download behavior.
references:
  - https://attack.mitre.org/techniques/T1059/001/
falsepositives:
  - Administrative scripts using encoded commands
tests:
  - name: Atomic Red Team T1059.001
    source: atomic-red-team
    test_id: "1"
detection:
  selection:
    EventID: 1
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
`

const cardStyle = {
  background: '#0f172a',
  border: '1px solid #1e293b',
  borderRadius: '16px',
  padding: '20px',
} as const

type AuthoringTab = {
  id: 'detection' | 'investigation' | 'hunt' | 'learning'
  label: string
  title: string
  description: string
  templateFormats: string[]
  suggestedPath: string
  workflow: string[]
}

const AUTHORING_TABS: AuthoringTab[] = [
  {
    id: 'detection',
    label: 'Detections',
    title: 'Detection engineering workflow',
    description: 'Author a detection, inspect scoring and validation, then preview backend conversions.',
    templateFormats: ['yaml', 'markdown', 'detection_engineering'],
    suggestedPath: 'detections/<platform>/<name>.yml or knowledge/detection-engineering/<topic>.md',
    workflow: ['Load a detection template.', 'Edit logic, ATT&CK, and metadata.', 'Inspect & score.', 'Preview Sigma, Splunk, KQL, or EQL conversion.'],
  },
  {
    id: 'investigation',
    label: 'Investigations',
    title: 'Investigation and IR workflow',
    description: 'Document cloud investigations, incident response case studies, and forensics-style writeups as reusable workspace artifacts.',
    templateFormats: ['incident_response', 'flaws_cloud'],
    suggestedPath: 'knowledge/incident-response-case-studies/<topic>.md or knowledge/flaws-cloud/<topic>.md',
    workflow: ['Load an investigation template.', 'Capture indicators, timeline, evidence, and root cause.', 'Inspect the normalized workspace output.', 'Reuse response actions and detection opportunities.'],
  },
  {
    id: 'hunt',
    label: 'Threat Hunts',
    title: 'Threat hunting workflow',
    description: 'Turn hunt hypotheses, queries, findings, and follow-up detections into normalized hunt content.',
    templateFormats: ['threat_hunt'],
    suggestedPath: 'knowledge/threat-hunts/<platform>/<name>.md',
    workflow: ['Load the threat-hunt template.', 'Document the hypothesis and queries.', 'Inspect the normalized content.', 'Promote findings into follow-on detections or investigations.'],
  },
  {
    id: 'learning',
    label: 'Learning & Labs',
    title: 'Learning and lab workflow',
    description: 'Capture learning paths, AWS study notes, and labs in the same system so they become portfolio-ready knowledge artifacts.',
    templateFormats: ['learning_path', 'aws_security_learning', 'lab'],
    suggestedPath: 'knowledge/learning-paths/, knowledge/aws-security-learning/, or knowledge/labs/',
    workflow: ['Load the matching learning or lab template.', 'Document concepts, environment, evidence, and lessons learned.', 'Inspect the normalized content.', 'Link out to detections, hunts, or follow-up investigations.'],
  },
] as const

const DEFAULT_SAVE_PATHS: Record<(typeof AUTHORING_TABS)[number]['id'], string> = {
  detection: 'detections/custom/new-detection.yml',
  investigation: 'knowledge/incident-response-case-studies/new-investigation.md',
  hunt: 'knowledge/threat-hunts/general/new-threat-hunt.md',
  learning: 'knowledge/learning-paths/new-learning-path.md',
}

function isWorkbenchTabId(value: string | null): value is WorkbenchTabId {
  return value === 'detection' || value === 'investigation' || value === 'hunt' || value === 'learning'
}

function inferWorkbenchTabFromContent(path: string, contentKind: string): WorkbenchTabId {
  const normalizedPath = String(path || '').toLowerCase()
  const normalizedKind = String(contentKind || '').toLowerCase()

  if (normalizedKind === 'hunt' || normalizedPath.includes('threat-hunts/')) {
    return 'hunt'
  }
  if (normalizedKind === 'learning_path' || normalizedKind === 'lab' || normalizedPath.includes('learning-paths/') || normalizedPath.includes('labs/')) {
    return 'learning'
  }
  if (normalizedKind === 'detection' || normalizedPath.startsWith('detections/')) {
    return 'detection'
  }
  return 'investigation'
}

export default function DetectionWorkbench() {
  const [content, setContent] = useState(SAMPLE_DETECTION_YAML)
  const [target, setTarget] = useState('splunk')
  const [templateCatalog, setTemplateCatalog] = useState<DetectionTemplateCatalog | null>(null)
  const [templateFormat, setTemplateFormat] = useState('yaml')
  const [activeTab, setActiveTab] = useState<(typeof AUTHORING_TABS)[number]['id']>('detection')
  const [savePath, setSavePath] = useState(DEFAULT_SAVE_PATHS.detection)
  const [inspectResult, setInspectResult] = useState<InspectResponse | null>(null)
  const [convertResult, setConvertResult] = useState<ConvertResponse | null>(null)
  const [saveResult, setSaveResult] = useState<SaveResponse | null>(null)
  const [repoStatus, setRepoStatus] = useState<RepoStatus | null>(null)
  const [repoDiff, setRepoDiff] = useState<RepoDiffResponse | null>(null)
  const [commitResult, setCommitResult] = useState<RepoCommitResponse | null>(null)
  const [commitMessage, setCommitMessage] = useState('')
  const [editingPath, setEditingPath] = useState<string | null>(null)
  const [editingName, setEditingName] = useState<string | null>(null)
  const [loadingEditContent, setLoadingEditContent] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [inspecting, setInspecting] = useState(false)
  const [converting, setConverting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [loadingRepoStatus, setLoadingRepoStatus] = useState(false)
  const [loadingRepoDiff, setLoadingRepoDiff] = useState(false)
  const [committing, setCommitting] = useState(false)

  const recommendations = useMemo(() => inspectResult?.score?.recommendations ?? [], [inspectResult])
  const repoActions = useMemo(() => getRepoActionDefinitions(), [])
  const repoSummary = useMemo(() => summarizeRepoStatus(repoStatus), [repoStatus])

  const activeAuthoringTab = useMemo(() => AUTHORING_TABS.find((tab) => tab.id === activeTab) ?? AUTHORING_TABS[0], [activeTab])

  const availableTemplates = useMemo(() => {
    const defaults = { yaml: { label: 'Canonical YAML', description: '', content: SAMPLE_DETECTION_YAML } }
    const templates = templateCatalog?.templates ?? defaults
    return Object.entries(templates).filter(([format]) => activeAuthoringTab.templateFormats.includes(format))
  }, [activeAuthoringTab, templateCatalog])

  useEffect(() => {
    async function loadTemplates() {
      try {
        const response = await fetch(`${API_BASE_URL}/detections/templates`)
        if (!response.ok) {
          throw new Error(`template request failed: ${response.status}`)
        }
        const body: DetectionTemplateCatalog = await response.json()
        setTemplateCatalog(body)
        setTemplateFormat(body.default_format)
      } catch {
        setTemplateCatalog(null)
      }
    }

    loadTemplates()
  }, [])

  useEffect(() => {
    const matching = availableTemplates.find(([format]) => format === templateFormat)
    if (!matching && availableTemplates[0]) {
      setTemplateFormat(availableTemplates[0][0])
    }
  }, [availableTemplates, templateFormat])

  useEffect(() => {
    if (!editingPath) {
      setSavePath(DEFAULT_SAVE_PATHS[activeTab])
    }
    setSaveResult(null)
    setErrorMessage(null)
  }, [activeTab, editingPath])

  async function loadRepoStatus() {
    setLoadingRepoStatus(true)
    try {
      const response = await fetch(`${API_BASE_URL}/repo/status`)
      const body = await response.json()
      if (!response.ok) {
        throw new Error(body?.detail || `repo status request failed: ${response.status}`)
      }
      setRepoStatus(body)
    } catch {
      setRepoStatus(null)
    } finally {
      setLoadingRepoStatus(false)
    }
  }

  useEffect(() => {
    loadRepoStatus()
  }, [])

  useEffect(() => {
    if (typeof window === 'undefined') {
      return
    }

    const params = new URLSearchParams(window.location.search)
    const requestedTab = params.get('tab')
    if (isWorkbenchTabId(requestedTab)) {
      setActiveTab(requestedTab)
    }

    const editPath = params.get('edit')
    if (!editPath) {
      return
    }

    async function loadEditableContent() {
      setLoadingEditContent(true)
      setErrorMessage(null)
      try {
        const response = await fetch(`${API_BASE_URL}/repo/content?path=${encodeURIComponent(editPath)}`)
        const body: RepoContentResponse | { detail?: string } = await response.json()
        if (!response.ok) {
          throw new Error('detail' in body && body.detail ? body.detail : `repo content request failed: ${response.status}`)
        }

        const repoContent = body as RepoContentResponse
        const inferredTab = isWorkbenchTabId(requestedTab) ? requestedTab : inferWorkbenchTabFromContent(repoContent.path, repoContent.content_kind)
        setActiveTab(inferredTab)
        setEditingPath(repoContent.path)
        setEditingName(repoContent.name)
        setSavePath(repoContent.path)
        setContent(repoContent.content)
        setInspectResult(null)
        setConvertResult(null)
        setSaveResult(null)
        setCommitResult(null)
        setCommitMessage(`Update ${repoContent.path}`)
      } catch (error) {
        setEditingPath(null)
        setEditingName(null)
        setErrorMessage(error instanceof Error ? error.message : 'The edit request failed. Check the API service and retry.')
      } finally {
        setLoadingEditContent(false)
      }
    }

    loadEditableContent()
  }, [])

  function loadTemplate(format: string) {
    const template = templateCatalog?.templates[format]
    if (template?.content) {
      setContent(template.content)
      setInspectResult(null)
      setConvertResult(null)
      setSaveResult(null)
      setErrorMessage(null)
      return
    }

    if (format === 'yaml') {
      setContent(SAMPLE_DETECTION_YAML)
      setInspectResult(null)
      setConvertResult(null)
      setSaveResult(null)
      setErrorMessage(null)
    }
  }

  async function inspectDetection() {
    setInspecting(true)
    setErrorMessage(null)
    setConvertResult(null)

    try {
      const response = await fetch(`${API_BASE_URL}/detections/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
      })
      const body = await response.json()
      setInspectResult(body)
      if (!response.ok) {
        setErrorMessage('Validation failed. Fix the content and inspect again.')
      }
    } catch {
      setInspectResult(null)
      setErrorMessage('The API request failed. Check that the FastAPI service is reachable and retry.')
    } finally {
      setInspecting(false)
    }
  }

  async function convertDetection() {
    setConverting(true)
    setErrorMessage(null)

    try {
      const response = await fetch(`${API_BASE_URL}/detections/convert`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, target }),
      })
      const body = await response.json()
      setConvertResult(body)
      if (!response.ok) {
        setErrorMessage('Conversion could not be generated. Inspect the content or fix validation errors first.')
      }
    } catch {
      setConvertResult(null)
      setErrorMessage('The conversion request failed. Check the API service and retry.')
    } finally {
      setConverting(false)
    }
  }

  async function saveToRepo() {
    setSaving(true)
    setErrorMessage(null)

    try {
      const response = await fetch(`${API_BASE_URL}/detections/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: savePath, content }),
      })
      const body: SaveResponse | { detail?: string } = await response.json()

      if (!response.ok) {
        setSaveResult(null)
        setErrorMessage('detail' in body && body.detail ? body.detail : 'Save failed. Inspect the content and repo path, then retry.')
        if ('valid' in body && body.valid === false) {
          setInspectResult(body)
        }
        return
      }

      const savedBody = body as SaveResponse
      setSaveResult(savedBody)
      setInspectResult(savedBody)
      setConvertResult(null)
      setCommitResult(null)
      if (!commitMessage.trim()) {
        setCommitMessage(`Update ${savedBody.path}`)
      }
      setErrorMessage(`Saved to ${savedBody.path}`)
      await loadRepoStatus()
    } catch {
      setSaveResult(null)
      setErrorMessage('The save request failed. Check the API service and retry.')
    } finally {
      setSaving(false)
    }
  }

  async function previewRepoDiff() {
    setLoadingRepoDiff(true)
    setErrorMessage(null)

    try {
      const params = new URLSearchParams()
      if (savePath.trim()) {
        params.set('path', savePath.trim())
      }
      const response = await fetch(`${API_BASE_URL}/repo/diff?${params.toString()}`)
      const body = await response.json()
      if (!response.ok) {
        throw new Error(body?.detail || `repo diff request failed: ${response.status}`)
      }
      setRepoDiff(body)
      setRepoStatus(body)
    } catch {
      setRepoDiff(null)
      setErrorMessage('The repo diff request failed. Check Git status and retry.')
    } finally {
      setLoadingRepoDiff(false)
    }
  }

  async function commitRepoChanges() {
    setCommitting(true)
    setErrorMessage(null)

    try {
      const response = await fetch(`${API_BASE_URL}/repo/commit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: commitMessage }),
      })
      const body = await response.json()
      if (!response.ok) {
        throw new Error(body?.detail || `repo commit request failed: ${response.status}`)
      }
      setCommitResult(body)
      setRepoDiff(null)
      setRepoStatus({ branch: body.branch, clean: true, changed_files: [] })
      setErrorMessage(`Committed ${body.commit.slice(0, 7)} on ${body.branch}`)
    } catch (error) {
      setCommitResult(null)
      setErrorMessage(error instanceof Error ? error.message : 'The repo commit request failed. Review the diff and retry.')
    } finally {
      setCommitting(false)
    }
  }

  return (
    <div style={{ display: 'grid', gap: '16px', marginTop: '16px' }}>
      <div style={cardStyle}>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
          {AUTHORING_TABS.map((tab) => {
            const active = tab.id === activeTab
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  background: active ? '#0f172a' : '#111827',
                  color: active ? '#e0f2fe' : '#cbd5e1',
                  border: active ? '1px solid #38bdf8' : '1px solid #334155',
                  borderRadius: '999px',
                  padding: '9px 13px',
                  cursor: 'pointer',
                  fontSize: '0.85rem',
                }}
              >
                {tab.label}
              </button>
            )
          })}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 0.7fr', gap: '16px', alignItems: 'start' }}>
          <div>
            <h3 style={{ margin: 0 }}>{activeAuthoringTab.title}</h3>
            <p style={{ color: '#94a3b8', marginBottom: 0 }}>{activeAuthoringTab.description}</p>
            {loadingEditContent ? (
              <p style={{ color: '#cbd5e1', marginTop: '10px', marginBottom: 0 }}>Loading repo content into the workbench…</p>
            ) : null}
            {editingPath ? (
              <div style={{ marginTop: '10px', display: 'grid', gap: '4px' }}>
                <div style={{ color: '#38bdf8', fontSize: '0.82rem', fontWeight: 700 }}>Editing existing artifact</div>
                <div style={{ color: '#e2e8f0' }}>{editingName ?? editingPath}</div>
                <div style={{ color: '#94a3b8', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace', fontSize: '0.85rem' }}>{editingPath}</div>
              </div>
            ) : null}
          </div>
          <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>Suggested repo path</div>
            <div style={{ marginTop: '6px', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace', fontSize: '0.88rem' }}>
              {activeAuthoringTab.suggestedPath}
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '16px' }}>
          <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginBottom: '8px' }}>Workflow</div>
            <ol style={{ margin: 0, paddingLeft: '18px', display: 'grid', gap: '6px' }}>
              {activeAuthoringTab.workflow.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </div>
          <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginBottom: '8px' }}>Available templates</div>
            <div style={{ display: 'grid', gap: '6px' }}>
              {availableTemplates.map(([format, template]) => (
                <div key={format}>
                  <div style={{ fontWeight: 700 }}>{template.label}</div>
                  <div style={{ color: '#94a3b8', fontSize: '0.88rem' }}>{template.description}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', alignItems: 'center', flexWrap: 'wrap', marginTop: '16px' }}>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
            <select
              value={templateFormat}
              onChange={(event) => setTemplateFormat(event.target.value)}
              style={{ background: '#111827', color: '#e2e8f0', border: '1px solid #334155', borderRadius: '10px', padding: '10px 12px' }}
            >
              {availableTemplates.map(([format, template]) => (
                <option key={format} value={format}>
                  {template.label}
                </option>
              ))}
            </select>
            <button
              onClick={() => loadTemplate(templateFormat)}
              style={{ background: '#111827', color: '#e2e8f0', border: '1px solid #334155', borderRadius: '10px', padding: '10px 14px', cursor: 'pointer' }}
            >
              Load template
            </button>
            <button
              onClick={inspectDetection}
              disabled={inspecting}
              style={{ background: '#0369a1', color: '#e0f2fe', border: 'none', borderRadius: '10px', padding: '10px 14px', cursor: 'pointer' }}
            >
              {inspecting ? 'Inspecting…' : 'Inspect & Score'}
            </button>
            <button
              onClick={saveToRepo}
              disabled={saving}
              style={{ background: '#14532d', color: '#dcfce7', border: 'none', borderRadius: '10px', padding: '10px 14px', cursor: 'pointer' }}
            >
              {saving ? 'Saving…' : 'Save to Repo'}
            </button>
            <button
              onClick={previewRepoDiff}
              disabled={loadingRepoDiff}
              style={{ background: '#1d4ed8', color: '#dbeafe', border: 'none', borderRadius: '10px', padding: '10px 14px', cursor: 'pointer' }}
            >
              {loadingRepoDiff ? 'Loading diff…' : 'Diff Preview'}
            </button>
            <button
              onClick={commitRepoChanges}
              disabled={committing || !commitMessage.trim()}
              style={{ background: '#7c3aed', color: '#f3e8ff', border: 'none', borderRadius: '10px', padding: '10px 14px', cursor: 'pointer' }}
            >
              {committing ? 'Committing…' : 'Commit from UI'}
            </button>
          </div>
          <div style={{ color: '#94a3b8', fontSize: '0.88rem' }}>
            Repo files are the source of truth. Save directly into detections/ or knowledge/.
          </div>
        </div>

        <div style={{ display: 'grid', gap: '8px', marginTop: '16px' }}>
          <label htmlFor="save-path" style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
            Repo save path
          </label>
          <input
            id="save-path"
            value={savePath}
            onChange={(event) => setSavePath(event.target.value)}
            spellCheck={false}
            style={{
              width: '100%',
              background: '#020617',
              color: '#e2e8f0',
              border: '1px solid #334155',
              borderRadius: '12px',
              padding: '12px 14px',
              fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
              fontSize: '0.92rem',
            }}
          />
          <div style={{ color: '#64748b', fontSize: '0.8rem' }}>
            Allowed roots: <code>detections/</code> and <code>knowledge/</code>. Allowed file types: <code>.yml</code>, <code>.yaml</code>, <code>.md</code>.
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '16px' }}>
          <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginBottom: '8px' }}>Git-aware actions</div>
            <div style={{ display: 'grid', gap: '8px' }}>
              {repoActions.map((action) => (
                <div key={action.id}>
                  <div style={{ fontWeight: 700 }}>{action.label}</div>
                  <div style={{ color: '#94a3b8', fontSize: '0.88rem' }}>{action.description}</div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginBottom: '8px' }}>Commit message</div>
            <input
              value={commitMessage}
              onChange={(event) => setCommitMessage(event.target.value)}
              placeholder="e.g. Add IAM threat hunt artifact"
              style={{
                width: '100%',
                background: '#020617',
                color: '#e2e8f0',
                border: '1px solid #334155',
                borderRadius: '12px',
                padding: '12px 14px',
                boxSizing: 'border-box',
              }}
            />
            <div style={{ color: '#64748b', fontSize: '0.8rem', marginTop: '8px' }}>
              Write the exact Git message to use when committing the current repo changes.
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '16px' }}>
          <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center' }}>
              <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>Repo status</div>
              <button
                onClick={loadRepoStatus}
                disabled={loadingRepoStatus}
                style={{ background: '#020617', color: '#cbd5e1', border: '1px solid #334155', borderRadius: '10px', padding: '8px 12px', cursor: 'pointer' }}
              >
                {loadingRepoStatus ? 'Refreshing…' : 'Refresh'}
              </button>
            </div>
            <div style={{ marginTop: '8px', color: '#e2e8f0' }}>{repoSummary}</div>
            <div style={{ display: 'grid', gap: '6px', marginTop: '12px' }}>
              {repoStatus?.changed_files?.length ? (
                repoStatus.changed_files.map((item) => (
                  <div key={`${item.status}-${item.path}`} style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace', fontSize: '0.86rem', color: '#cbd5e1' }}>
                    <code>{item.status}</code> {item.path}
                  </div>
                ))
              ) : (
                <div style={{ color: '#64748b', fontSize: '0.86rem' }}>No uncommitted repo changes detected.</div>
              )}
            </div>
          </div>
          <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginBottom: '8px' }}>Latest commit action</div>
            {commitResult ? (
              <div style={{ display: 'grid', gap: '8px' }}>
                <div><strong>Branch:</strong> {commitResult.branch}</div>
                <div><strong>Commit:</strong> <code>{commitResult.commit}</code></div>
                <div><strong>Message:</strong> {commitResult.message}</div>
              </div>
            ) : (
              <div style={{ color: '#64748b', fontSize: '0.86rem' }}>No UI commit has been created in this session yet.</div>
            )}
          </div>
        </div>

        <textarea
          value={content}
          onChange={(event) => setContent(event.target.value)}
          spellCheck={false}
          style={{
            width: '100%',
            minHeight: '420px',
            marginTop: '16px',
            background: '#020617',
            color: '#e2e8f0',
            border: '1px solid #334155',
            borderRadius: '14px',
            padding: '16px',
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
            fontSize: '0.95rem',
            lineHeight: 1.5,
          }}
        />
        {errorMessage ? (
          <div style={{ marginTop: '16px', background: errorMessage.startsWith('Saved to ') ? '#052e16' : '#3f0d16', border: errorMessage.startsWith('Saved to ') ? '1px solid #166534' : '1px solid #7f1d1d', color: errorMessage.startsWith('Saved to ') ? '#bbf7d0' : '#fecaca', borderRadius: '12px', padding: '12px 14px' }}>
            {errorMessage}
          </div>
        ) : null}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <div style={cardStyle}>
          <h3 style={{ marginTop: 0 }}>Inspection Results</h3>
          {inspectResult?.valid && inspectResult.detection && inspectResult.score ? (
            <div style={{ display: 'grid', gap: '14px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <Stat label="Detection ID" value={inspectResult.detection.id} />
                <Stat label="Overall Score" value={String(inspectResult.score.overall_score)} />
                <Stat label="Severity" value={inspectResult.detection.severity} />
                <Stat label="Status" value={inspectResult.detection.status} />
                <Stat label="ATT&CK Technique" value={inspectResult.detection.attack.technique} />
                <Stat label="ATT&CK Tactic" value={inspectResult.detection.attack.tactic} />
                <Stat label="Source Format" value={inspectResult.source_format ?? 'unknown'} />
                <Stat label="Normalized From" value={inspectResult.normalized_from ?? 'unknown'} />
                <Stat label="Canonical Model" value={inspectResult.canonical_model_version ?? 'unknown'} />
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>Title</div>
                <div style={{ marginTop: '4px', fontWeight: 700 }}>{inspectResult.detection.title}</div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.86rem' }}>Description</div>
                <div style={{ marginTop: '4px' }}>{inspectResult.detection.description}</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: '10px' }}>
                <ScorePill label="Coverage" value={inspectResult.score.coverage_score} />
                <ScorePill label="Specificity" value={inspectResult.score.specificity_score} />
                <ScorePill label="Metadata" value={inspectResult.score.metadata_score} />
                <ScorePill label="Maintainability" value={inspectResult.score.maintainability_score} />
                <ScorePill label="FP Risk" value={inspectResult.score.false_positive_risk} />
              </div>
            </div>
          ) : inspectResult?.errors?.length ? (
            <div>
              <div style={{ color: '#fca5a5', fontWeight: 700 }}>Validation errors</div>
              <ul style={{ marginBottom: 0 }}>
                {inspectResult.errors.map((error, index) => (
                  <li key={`${error.loc.join('.')}-${index}`}>
                    <code>{error.loc.join('.')}</code>: {error.msg}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div style={{ color: '#94a3b8' }}>
              Submit content from any tab to see parsed metadata, validation state, and score breakdown.
            </div>
          )}
        </div>

        <div style={cardStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0 }}>Recommendations & Conversion</h3>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
              <select
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                style={{ background: '#111827', color: '#e2e8f0', border: '1px solid #334155', borderRadius: '10px', padding: '10px 12px' }}
              >
                <option value="splunk">Splunk</option>
                <option value="sigma">Sigma</option>
                <option value="kql">KQL</option>
                <option value="eql">EQL</option>
              </select>
              <button
                onClick={convertDetection}
                disabled={converting}
                style={{ background: '#14532d', color: '#dcfce7', border: 'none', borderRadius: '10px', padding: '10px 14px', cursor: 'pointer' }}
              >
                {converting ? 'Converting…' : 'Preview Conversion'}
              </button>
            </div>
          </div>

          <div style={{ marginTop: '16px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.86rem', marginBottom: '8px' }}>Recommendations</div>
            {saveResult?.saved ? (
              <div style={{ background: '#052e16', border: '1px solid #166534', color: '#bbf7d0', borderRadius: '12px', padding: '12px 14px', marginBottom: '12px' }}>
                Saved to <code>{saveResult.path}</code> under <code>{saveResult.repo_root}</code>
              </div>
            ) : null}
            {recommendations.length > 0 ? (
              <ul style={{ marginTop: 0 }}>
                {recommendations.map((recommendation) => (
                  <li key={recommendation}>{recommendation}</li>
                ))}
              </ul>
            ) : inspectResult?.valid ? (
              <div style={{ color: '#94a3b8' }}>No remediation recommendations were generated for this content.</div>
            ) : (
              <div style={{ color: '#94a3b8' }}>Inspect content to generate recommendations.</div>
            )}
          </div>

          <div style={{ marginTop: '16px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.86rem', marginBottom: '8px' }}>Diff Preview</div>
            {repoDiff?.diff ? (
              <pre
                style={{
                  margin: 0,
                  padding: '16px',
                  background: '#020617',
                  border: '1px solid #334155',
                  borderRadius: '14px',
                  overflowX: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  color: '#e2e8f0',
                  maxHeight: '260px',
                }}
              >
                {repoDiff.diff}
              </pre>
            ) : (
              <div style={{ color: '#94a3b8' }}>Save content, then use Diff Preview to inspect the current repo delta before committing.</div>
            )}
          </div>

          <div style={{ marginTop: '16px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.86rem', marginBottom: '8px' }}>Conversion Preview</div>
            {convertResult?.valid && convertResult.content ? (
              <div style={{ display: 'grid', gap: '12px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '10px' }}>
                  <Stat label="Source Format" value={convertResult.source_format ?? 'unknown'} />
                  <Stat label="Normalized From" value={convertResult.normalized_from ?? 'unknown'} />
                  <Stat label="Canonical Model" value={convertResult.canonical_model_version ?? 'unknown'} />
                </div>
                <pre
                  style={{
                    margin: 0,
                    padding: '16px',
                    background: '#020617',
                    border: '1px solid #334155',
                    borderRadius: '14px',
                    overflowX: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                    color: '#e2e8f0',
                  }}
                >
                  {convertResult.content}
                </pre>
              </div>
            ) : convertResult?.errors?.length ? (
              <ul style={{ marginBottom: 0 }}>
                {convertResult.errors.map((error, index) => (
                  <li key={`${error.loc.join('.')}-${index}`}>
                    <code>{error.loc.join('.')}</code>: {error.msg}
                  </li>
                ))}
              </ul>
            ) : (
              <div style={{ color: '#94a3b8' }}>Choose a target and preview the converted output after inspection.</div>
            )}
          </div>
        </div>
      </div>
    </div>
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

function ScorePill({ label, value }: { label: string; value: number }) {
  return (
    <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '12px', padding: '12px' }}>
      <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>{label}</div>
      <div style={{ marginTop: '6px', fontWeight: 700 }}>{value}</div>
    </div>
  )
}
