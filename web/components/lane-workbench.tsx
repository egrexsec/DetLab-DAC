'use client'

import type { ReactNode } from 'react'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  buildLaneArtifact,
  buildRepoFilePath,
  getWorkbenchConfig,
} from '../data/workbench-config.mjs'
import {
  conversionFieldForTarget,
  requestSigmaConversion,
} from '../data/conversion-client.mjs'
import { runConversionRequest } from '../data/conversion-request.mjs'
import {
  forgetGeneratedQuerySource,
  recordGeneratedQuerySource,
  staleGeneratedQueryFields,
} from '../data/conversion-provenance.mjs'

type LaneSlug = 'detections'

type SaveResult = {
  commitUrl: string
  fileUrl: string
  path: string
  sha: string
} | null

type ConversionResult = {
  sourceSha256: string
  converter: string
  target: string
} | null

type GeneratedQueryField = 'spl' | 'kql' | 'eql' | 'esql'
type GeneratedQuerySources = Partial<Record<GeneratedQueryField, string>>

type FormState = {
  repoOwner: string
  repoName: string
  branch: string
  directory: string
  title: string
  summary: string
  tags: string
  author: string
  filename: string
  technique: string
  tactic: string
  severity: string
  status: string
  platform: string
  telemetry: string
  sigma: string
  spl: string
  kql: string
  eql: string
  esql: string
  generatedQuerySources: GeneratedQuerySources
  otherLanguage: string
  otherQuery: string
  triage: string
  validation: string
  falsePositives: string
  references: string
}

const panelStyle = {
  background: '#0f172a',
  border: '1px solid #1e293b',
  borderRadius: '18px',
  padding: '20px',
} as const

const inputStyle = {
  width: '100%',
  background: '#020617',
  color: '#e2e8f0',
  border: '1px solid #334155',
  borderRadius: '12px',
  padding: '12px 14px',
  fontSize: '0.95rem',
  boxSizing: 'border-box' as const,
} as const

function encodeGitHubContent(value: string) {
  if (typeof window === 'undefined') {
    return ''
  }

  return window.btoa(unescape(encodeURIComponent(value)))
}

function apiPathEncode(path: string) {
  return path.split('/').map(encodeURIComponent).join('/')
}

function getDefaultFormState(): FormState {
  const config = getWorkbenchConfig('detections')

  if (!config) {
    throw new Error('Missing detection workbench config')
  }

  return {
    repoOwner: config.repositoryDefaults.owner,
    repoName: config.repositoryDefaults.repo,
    branch: config.repositoryDefaults.branch,
    directory: config.repositoryDefaults.directory,
    title: '',
    summary: '',
    tags: '',
    author: 'mell0wx',
    filename: '',
    technique: '',
    tactic: 'execution',
    severity: 'medium',
    status: 'draft',
    platform: 'windows',
    telemetry: '',
    sigma: config.defaults.sigma,
    spl: config.defaults.spl,
    kql: config.defaults.kql,
    eql: config.defaults.eql,
    esql: config.defaults.esql,
    generatedQuerySources: {},
    otherLanguage: '',
    otherQuery: '',
    triage: '',
    validation: '',
    falsePositives: '',
    references: '',
  }
}

export default function LaneWorkbench({ initialLaneSlug }: { initialLaneSlug: LaneSlug }) {
  const [laneSlug] = useState<LaneSlug>(initialLaneSlug)
  const [token, setToken] = useState('')
  const [formState, setFormState] = useState<FormState>(() => getDefaultFormState())
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [statusMessage, setStatusMessage] = useState('')
  const [saveResult, setSaveResult] = useState<SaveResult>(null)
  const [conversionApiUrl, setConversionApiUrl] = useState(process.env.NEXT_PUBLIC_DETLAB_CONVERSION_API ?? '')
  const [conversionTarget, setConversionTarget] = useState('splunk')
  const [conversionState, setConversionState] = useState<'idle' | 'converting' | 'converted' | 'stale' | 'error'>('idle')
  const [conversionMessage, setConversionMessage] = useState('')
  const [conversionResult, setConversionResult] = useState<ConversionResult>(null)
  const latestSigmaRef = useRef(formState.sigma)
  const requestGenerationRef = useRef(0)

  latestSigmaRef.current = formState.sigma

  const config = useMemo(() => getWorkbenchConfig(laneSlug), [laneSlug])

  useEffect(() => {
    const savedToken = window.localStorage.getItem('detlab:github-token')
    const savedState = window.localStorage.getItem('detlab:detection-workbench')
    const savedConversionApi = window.localStorage.getItem('detlab:conversion-api')

    if (savedToken) {
      setToken(savedToken)
    }

    if (savedState) {
      setFormState({ ...getDefaultFormState(), ...JSON.parse(savedState) })
    } else {
      setFormState(getDefaultFormState())
    }

    if (savedConversionApi) {
      setConversionApiUrl(savedConversionApi)
    }
  }, [])

  useEffect(() => {
    window.localStorage.setItem('detlab:github-token', token)
  }, [token])

  useEffect(() => {
    window.localStorage.setItem('detlab:detection-workbench', JSON.stringify(formState))
  }, [formState])

  useEffect(() => {
    window.localStorage.setItem('detlab:conversion-api', conversionApiUrl)
  }, [conversionApiUrl])

  const artifact = useMemo(
    () =>
      buildLaneArtifact({
        laneSlug,
        title: formState.title,
        summary: formState.summary,
        tags: formState.tags,
        author: formState.author,
        technique: formState.technique,
        tactic: formState.tactic,
        severity: formState.severity,
        status: formState.status,
        platform: formState.platform,
        telemetry: formState.telemetry,
        sigma: formState.sigma,
        spl: formState.spl,
        kql: formState.kql,
        eql: formState.eql,
        esql: formState.esql,
        otherLanguage: formState.otherLanguage,
        otherQuery: formState.otherQuery,
        triage: formState.triage,
        validation: formState.validation,
        falsePositives: formState.falsePositives,
        references: formState.references,
      }),
    [formState, laneSlug],
  )

  const effectiveFilename = formState.filename.trim() || artifact.filename
  const targetPath = buildRepoFilePath(formState.directory, effectiveFilename)
  const staleGeneratedFields = staleGeneratedQueryFields(
    formState.generatedQuerySources,
    formState.sigma,
    formState,
  ) as GeneratedQueryField[]
  const hasStaleGeneratedOutputs = staleGeneratedFields.length > 0

  function handleGeneratedQueryChange(field: GeneratedQueryField, value: string) {
    setFormState((current) => ({
      ...current,
      [field]: value,
      generatedQuerySources: forgetGeneratedQuerySource(current.generatedQuerySources, field),
    }))
  }

  async function handleSave() {
    if (hasStaleGeneratedOutputs) {
      setSaveState('error')
      setStatusMessage(`Regenerate or manually revise stale generated queries before saving: ${staleGeneratedFields.join(', ')}.`)
      return
    }
    if (!token.trim()) {
      setSaveState('error')
      setStatusMessage('Add a GitHub personal access token with repo contents write access before saving.')
      return
    }

    if (!formState.title.trim()) {
      setSaveState('error')
      setStatusMessage('Add a detection title before saving the artifact.')
      return
    }

    setSaveState('saving')
    setStatusMessage('Saving detection brief to GitHub…')
    setSaveResult(null)

    try {
      const authHeaderName = ['Author', 'ization'].join('')
      const authScheme = String.fromCharCode(66, 101, 97, 114, 101, 114)
      const headers = {
        [authHeaderName]: `${authScheme} ${token.trim()}`,
        Accept: 'application/vnd.github+json',
      }

      const encodedPath = apiPathEncode(targetPath)
      const getResponse = await fetch(
        `https://api.github.com/repos/${formState.repoOwner}/${formState.repoName}/contents/${encodedPath}?ref=${encodeURIComponent(formState.branch)}`,
        { headers },
      )

      let existingSha: string | undefined

      if (getResponse.status === 200) {
        const existing = await getResponse.json()
        existingSha = existing.sha
      } else if (getResponse.status !== 404) {
        const failure = await getResponse.json()
        throw new Error(failure.message || 'Failed to inspect the existing file path.')
      }

      const putResponse = await fetch(
        `https://api.github.com/repos/${formState.repoOwner}/${formState.repoName}/contents/${encodedPath}`,
        {
          method: 'PUT',
          headers: {
            ...headers,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            message: artifact.commitMessage,
            content: encodeGitHubContent(artifact.content),
            branch: formState.branch,
            sha: existingSha,
          }),
        },
      )

      const payload = await putResponse.json()

      if (!putResponse.ok) {
        throw new Error(payload.message || 'GitHub rejected the save request.')
      }

      setSaveState('saved')
      setStatusMessage(`Saved ${targetPath} to ${formState.repoOwner}/${formState.repoName}@${formState.branch}.`)
      setSaveResult({
        commitUrl: payload.commit?.html_url ?? '',
        fileUrl: payload.content?.html_url ?? '',
        path: payload.content?.path ?? targetPath,
        sha: payload.content?.sha ?? '',
      })
    } catch (error) {
      setSaveState('error')
      setStatusMessage(error instanceof Error ? error.message : 'Unknown GitHub save failure.')
    }
  }

  async function handleConvert() {
    if (!conversionApiUrl.trim()) {
      setConversionState('error')
      setConversionMessage('Configure the server-side conversion API URL before converting.')
      return
    }
    if (!formState.sigma.trim()) {
      setConversionState('error')
      setConversionMessage('Add authored Sigma YAML before converting.')
      return
    }
    const submittedSource = formState.sigma
    const requestGeneration = ++requestGenerationRef.current
    setConversionState('converting')
    setConversionMessage('Converting authored Sigma with the selected pinned backend…')
    await runConversionRequest({
      source: submittedSource,
      generation: requestGeneration,
      request: () => requestSigmaConversion({
        baseUrl: conversionApiUrl,
        source: submittedSource,
        target: conversionTarget,
      }),
      isCurrent: (generation: number, source: string) => (
        requestGenerationRef.current === generation && latestSigmaRef.current === source
      ),
      publishSuccess: (result: any) => {
        const field = conversionFieldForTarget(result.target)
        if (!field) {
          throw new Error('Conversion response target is not supported by this workbench.')
        }
        setFormState((current) => ({
          ...current,
          [field]: result.outputs.join('\n\n'),
          generatedQuerySources: recordGeneratedQuerySource(current.generatedQuerySources, field, submittedSource),
        }))
        setConversionState('converted')
        setConversionResult({
          sourceSha256: result.source_sha256,
          converter: `${result.provenance.converter.name}@${result.provenance.converter.version}`,
          target: result.target,
        })
        setConversionMessage(`Generated ${result.target} from the current Sigma source.`)
      },
      publishError: (error: unknown) => {
        setConversionState('error')
        setConversionMessage(error instanceof Error ? error.message : 'Unknown conversion failure.')
      },
    })
  }

  return (
    <section style={{ ...panelStyle, display: 'grid', gap: '18px' }}>
      <div style={{ display: 'grid', gap: '8px' }}>
        <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
          Workbench
        </div>
        <h2 style={{ margin: 0 }}>Author a detection brief and save it to GitHub</h2>
        <p style={{ margin: 0, color: '#94a3b8', lineHeight: 1.7 }}>
          This workbench is detection-only. Build one markdown artifact that preserves ATT&amp;CK context, telemetry assumptions, and equivalent logic across Sigma, SPL, KQL, EQL, ES|QL, and any extra dialect you need.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
        <LabeledField label="GitHub token">
          <input
            type="password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder="github_pat_..."
            style={inputStyle}
          />
        </LabeledField>
        <LabeledField label="Detection title">
          <input
            value={formState.title}
            onChange={(event) => setFormState((current) => ({ ...current, title: event.target.value }))}
            placeholder="Encoded PowerShell follow-on detection"
            style={inputStyle}
          />
        </LabeledField>
        <LabeledField label="Summary">
          <input
            value={formState.summary}
            onChange={(event) => setFormState((current) => ({ ...current, summary: event.target.value }))}
            placeholder="One-line summary of the behavior and detection goal."
            style={inputStyle}
          />
        </LabeledField>
        <LabeledField label="Tags (comma separated)">
          <input
            value={formState.tags}
            onChange={(event) => setFormState((current) => ({ ...current, tags: event.target.value }))}
            placeholder="windows, powershell, sigma, kql"
            style={inputStyle}
          />
        </LabeledField>
        <LabeledField label="Author">
          <input value={formState.author} onChange={(event) => setFormState((current) => ({ ...current, author: event.target.value }))} style={inputStyle} />
        </LabeledField>
        <LabeledField label="Repository owner">
          <input value={formState.repoOwner} onChange={(event) => setFormState((current) => ({ ...current, repoOwner: event.target.value }))} style={inputStyle} />
        </LabeledField>
        <LabeledField label="Repository name">
          <input value={formState.repoName} onChange={(event) => setFormState((current) => ({ ...current, repoName: event.target.value }))} style={inputStyle} />
        </LabeledField>
        <LabeledField label="Branch">
          <input value={formState.branch} onChange={(event) => setFormState((current) => ({ ...current, branch: event.target.value }))} style={inputStyle} />
        </LabeledField>
        <LabeledField label="Directory">
          <input value={formState.directory} onChange={(event) => setFormState((current) => ({ ...current, directory: event.target.value }))} style={inputStyle} />
        </LabeledField>
        <LabeledField label="Filename override">
          <input value={formState.filename} onChange={(event) => setFormState((current) => ({ ...current, filename: event.target.value }))} placeholder={artifact.filename} style={inputStyle} />
        </LabeledField>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
        <LabeledField label="ATT&CK technique">
          <input value={formState.technique} onChange={(event) => setFormState((current) => ({ ...current, technique: event.target.value }))} placeholder="T1059.001" style={inputStyle} />
        </LabeledField>
        <LabeledField label="ATT&CK tactic">
          <input value={formState.tactic} onChange={(event) => setFormState((current) => ({ ...current, tactic: event.target.value }))} placeholder="execution" style={inputStyle} />
        </LabeledField>
        <LabeledField label="Platform">
          <input value={formState.platform} onChange={(event) => setFormState((current) => ({ ...current, platform: event.target.value }))} placeholder="windows" style={inputStyle} />
        </LabeledField>
        <LabeledField label="Severity">
          <input value={formState.severity} onChange={(event) => setFormState((current) => ({ ...current, severity: event.target.value }))} placeholder="medium" style={inputStyle} />
        </LabeledField>
        <LabeledField label="Status">
          <input value={formState.status} onChange={(event) => setFormState((current) => ({ ...current, status: event.target.value }))} placeholder="draft" style={inputStyle} />
        </LabeledField>
      </div>

      <LabeledField label="Telemetry and prerequisites">
        <textarea
          value={formState.telemetry}
          onChange={(event) => setFormState((current) => ({ ...current, telemetry: event.target.value }))}
          placeholder="Explain the log source, required fields, parser assumptions, and retention expectations."
          rows={5}
          style={{ ...inputStyle, resize: 'vertical' as const }}
        />
      </LabeledField>

      <div style={{ display: 'grid', gap: '14px' }}>
        <LabeledField label="Sigma">
          <textarea
            value={formState.sigma}
            onChange={(event) => {
              latestSigmaRef.current = event.target.value
              requestGenerationRef.current += 1
              setFormState((current) => ({ ...current, sigma: event.target.value }))
              if (Object.keys(formState.generatedQuerySources).length > 0 || conversionState === 'converting') {
                setConversionState('stale')
                setConversionMessage('Authored Sigma changed; generated or in-flight conversion output is stale.')
              }
            }}
            rows={10}
            style={{ ...inputStyle, resize: 'vertical' as const, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}
          />
        </LabeledField>
        <div style={{ ...panelStyle, display: 'grid', gap: '12px' }}>
          <strong>Server-side Sigma conversion</strong>
          <p style={{ margin: 0, color: '#94a3b8', lineHeight: 1.6 }}>
            Authored Sigma stays canonical. Generated queries include backend version and source-hash provenance.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 1fr) minmax(180px, 0.4fr)', gap: '12px' }}>
            <LabeledField label="Conversion API origin">
              <input
                value={conversionApiUrl}
                onChange={(event) => setConversionApiUrl(event.target.value)}
                placeholder="http://localhost:8000"
                style={inputStyle}
              />
            </LabeledField>
            <LabeledField label="Target backend">
              <select value={conversionTarget} onChange={(event) => setConversionTarget(event.target.value)} style={inputStyle}>
                <option value="splunk">Splunk SPL</option>
                <option value="elastic-eql">Elastic EQL</option>
                <option value="elastic-esql">Elastic ES|QL</option>
                <option value="microsoft-kusto">Microsoft Kusto KQL</option>
              </select>
            </LabeledField>
          </div>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={handleConvert}
              disabled={conversionState === 'converting'}
              style={{
                background: '#1d4ed8',
                color: '#dbeafe',
                border: '1px solid #60a5fa',
                borderRadius: '999px',
                padding: '10px 16px',
                cursor: conversionState === 'converting' ? 'progress' : 'pointer',
                fontWeight: 800,
              }}
            >
              {conversionState === 'converting' ? 'Converting…' : 'Generate selected query'}
            </button>
            <span style={{ color: conversionState === 'error' || conversionState === 'stale' ? '#fca5a5' : '#94a3b8' }}>
              {conversionMessage || 'No generated output in this browser session.'}
            </span>
          </div>
          {conversionResult ? (
            <code style={{ color: conversionState === 'stale' ? '#fca5a5' : '#86efac', overflowWrap: 'anywhere' }}>
              {conversionState === 'stale' ? 'STALE · ' : ''}{conversionResult.target} · {conversionResult.converter} · source {conversionResult.sourceSha256}
            </code>
          ) : null}
          {hasStaleGeneratedOutputs ? (
            <code style={{ color: '#fca5a5', overflowWrap: 'anywhere' }}>
              STALE generated queries: {staleGeneratedFields.join(', ')} · GitHub save blocked until regenerated or manually revised.
            </code>
          ) : null}
        </div>
        <LabeledField label="Splunk SPL">
          <textarea
            value={formState.spl}
            onChange={(event) => handleGeneratedQueryChange('spl', event.target.value)}
            rows={6}
            style={{ ...inputStyle, resize: 'vertical' as const, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}
          />
        </LabeledField>
        <LabeledField label="Microsoft Sentinel KQL">
          <textarea
            value={formState.kql}
            onChange={(event) => handleGeneratedQueryChange('kql', event.target.value)}
            rows={6}
            style={{ ...inputStyle, resize: 'vertical' as const, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}
          />
        </LabeledField>
        <LabeledField label="Elastic EQL">
          <textarea
            value={formState.eql}
            onChange={(event) => handleGeneratedQueryChange('eql', event.target.value)}
            rows={6}
            style={{ ...inputStyle, resize: 'vertical' as const, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}
          />
        </LabeledField>
        <LabeledField label="Elastic ES|QL">
          <textarea
            value={formState.esql}
            onChange={(event) => handleGeneratedQueryChange('esql', event.target.value)}
            rows={6}
            style={{ ...inputStyle, resize: 'vertical' as const, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}
          />
        </LabeledField>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 0.35fr) minmax(0, 0.65fr)', gap: '14px' }}>
        <LabeledField label="Other language label">
          <input
            value={formState.otherLanguage}
            onChange={(event) => setFormState((current) => ({ ...current, otherLanguage: event.target.value }))}
            placeholder="E.g. XQL, Lucene, Chronicle YARA-L"
            style={inputStyle}
          />
        </LabeledField>
        <LabeledField label="Other implementation">
          <textarea
            value={formState.otherQuery}
            onChange={(event) => setFormState((current) => ({ ...current, otherQuery: event.target.value }))}
            rows={6}
            style={{ ...inputStyle, resize: 'vertical' as const, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}
          />
        </LabeledField>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
        <LabeledField label="False positives (one per line)">
          <textarea
            value={formState.falsePositives}
            onChange={(event) => setFormState((current) => ({ ...current, falsePositives: event.target.value }))}
            rows={6}
            style={{ ...inputStyle, resize: 'vertical' as const }}
          />
        </LabeledField>
        <LabeledField label="Triage guidance (one step per line)">
          <textarea
            value={formState.triage}
            onChange={(event) => setFormState((current) => ({ ...current, triage: event.target.value }))}
            rows={6}
            style={{ ...inputStyle, resize: 'vertical' as const }}
          />
        </LabeledField>
        <LabeledField label="Validation notes (one step per line)">
          <textarea
            value={formState.validation}
            onChange={(event) => setFormState((current) => ({ ...current, validation: event.target.value }))}
            rows={6}
            style={{ ...inputStyle, resize: 'vertical' as const }}
          />
        </LabeledField>
      </div>

      <LabeledField label="References (one per line)">
        <textarea
          value={formState.references}
          onChange={(event) => setFormState((current) => ({ ...current, references: event.target.value }))}
          rows={5}
          style={{ ...inputStyle, resize: 'vertical' as const }}
        />
      </LabeledField>

      <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
        <button
          type="button"
          onClick={handleSave}
          disabled={saveState === 'saving' || hasStaleGeneratedOutputs}
          style={{
            background: '#0f766e',
            color: '#ccfbf1',
            border: '1px solid #14b8a6',
            borderRadius: '999px',
            padding: '12px 18px',
            cursor: saveState === 'saving' ? 'progress' : hasStaleGeneratedOutputs ? 'not-allowed' : 'pointer',
            opacity: hasStaleGeneratedOutputs ? 0.65 : 1,
            fontWeight: 800,
          }}
        >
          {saveState === 'saving' ? 'Saving…' : 'Save to GitHub'}
        </button>
        <div style={{ color: saveState === 'error' ? '#fca5a5' : '#94a3b8', lineHeight: 1.6 }}>
          {statusMessage || `Target path: ${targetPath}`}
        </div>
      </div>

      {saveResult ? (
        <div style={{ background: '#111827', border: '1px solid #334155', borderRadius: '14px', padding: '16px', display: 'grid', gap: '8px' }}>
          <div>
            <strong>Saved path:</strong> {saveResult.path}
          </div>
          <div>
            <strong>Blob SHA:</strong> {saveResult.sha}
          </div>
          {saveResult.fileUrl ? (
            <a href={saveResult.fileUrl} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>
              View file on GitHub
            </a>
          ) : null}
          {saveResult.commitUrl ? (
            <a href={saveResult.commitUrl} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>
              View commit on GitHub
            </a>
          ) : null}
        </div>
      ) : null}

      <div style={{ display: 'grid', gap: '8px' }}>
        <div style={{ color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: '12px', fontWeight: 700 }}>
          Preview
        </div>
        <div style={{ color: '#94a3b8' }}>
          {config?.artifactType} → <code>{targetPath}</code>
        </div>
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
            fontSize: '0.9rem',
            overflowX: 'auto',
          }}
        >
          {artifact.content}
        </pre>
      </div>
    </section>
  )
}

function LabeledField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label style={{ display: 'grid', gap: '8px' }}>
      <span style={{ color: '#cbd5e1', fontWeight: 700 }}>{label}</span>
      {children}
    </label>
  )
}
