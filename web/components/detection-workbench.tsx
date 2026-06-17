'use client'

import { useMemo, useState } from 'react'

type ValidationErrorRow = {
  loc: Array<string | number>
  msg: string
  type: string
}

type InspectResponse = {
  valid: boolean
  errors: ValidationErrorRow[]
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

export default function DetectionWorkbench() {
  const [content, setContent] = useState(SAMPLE_DETECTION_YAML)
  const [target, setTarget] = useState('splunk')
  const [inspectResult, setInspectResult] = useState<InspectResponse | null>(null)
  const [convertResult, setConvertResult] = useState<ConvertResponse | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [inspecting, setInspecting] = useState(false)
  const [converting, setConverting] = useState(false)

  const recommendations = useMemo(() => inspectResult?.score?.recommendations ?? [], [inspectResult])

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
        setErrorMessage('Validation failed. Fix the detection content and inspect again.')
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
        setErrorMessage('Conversion could not be generated. Inspect the detection or fix validation errors first.')
      }
    } catch {
      setConvertResult(null)
      setErrorMessage('The conversion request failed. Check the API service and retry.')
    } finally {
      setConverting(false)
    }
  }

  return (
    <div style={{ display: 'grid', gap: '16px', marginTop: '16px' }}>
      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div>
            <h3 style={{ margin: 0 }}>Create & Inspect Detection</h3>
            <p style={{ color: '#94a3b8', marginBottom: 0 }}>
              Draft a detection in YAML, inspect validation and scoring results, then optionally preview a backend conversion.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <button
              onClick={() => setContent(SAMPLE_DETECTION_YAML)}
              style={{ background: '#111827', color: '#e2e8f0', border: '1px solid #334155', borderRadius: '10px', padding: '10px 14px', cursor: 'pointer' }}
            >
              Load sample
            </button>
            <button
              onClick={inspectDetection}
              disabled={inspecting}
              style={{ background: '#0369a1', color: '#e0f2fe', border: 'none', borderRadius: '10px', padding: '10px 14px', cursor: 'pointer' }}
            >
              {inspecting ? 'Inspecting…' : 'Inspect & Score'}
            </button>
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
          <div style={{ marginTop: '16px', background: '#3f0d16', border: '1px solid #7f1d1d', color: '#fecaca', borderRadius: '12px', padding: '12px 14px' }}>
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
              Submit a detection to see parsed metadata, validation state, and score breakdown.
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
            {recommendations.length > 0 ? (
              <ul style={{ marginTop: 0 }}>
                {recommendations.map((recommendation) => (
                  <li key={recommendation}>{recommendation}</li>
                ))}
              </ul>
            ) : inspectResult?.valid ? (
              <div style={{ color: '#94a3b8' }}>No remediation recommendations were generated for this detection.</div>
            ) : (
              <div style={{ color: '#94a3b8' }}>Inspect a detection to generate recommendations.</div>
            )}
          </div>

          <div style={{ marginTop: '16px' }}>
            <div style={{ color: '#94a3b8', fontSize: '0.86rem', marginBottom: '8px' }}>Conversion Preview</div>
            {convertResult?.valid && convertResult.content ? (
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
