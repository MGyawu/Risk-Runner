import { useEffect, useState } from 'react'
import { api, type Finding, type FindingStatus } from '../api'
import { ErrorNote, Pill, ScoreBadge, TypePill } from './ui'

const FACTOR_LABELS: Record<string, string> = {
  technical: 'Technical severity (0-10)',
  likelihood: 'Exploit likelihood ×',
  criticality: 'Business criticality ×',
  exposure: 'Exposure ×',
  data_sensitivity: 'Data sensitivity ×',
  compliance: 'Compliance scope ×',
  revenue: 'Revenue impact ×',
  business: 'Business multiplier (total)',
}

export function FindingDrawer({
  finding: f,
  onClose,
  onChange,
}: {
  finding: Finding
  onClose: () => void
  onChange: (f: Finding) => void
}) {
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  async function setStatus(status: FindingStatus) {
    setBusy(true)
    try {
      onChange(await api.updateFinding(f.id, status))
      setError(null)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()} aria-label="Finding details">
        <header className="drawer-head">
          <ScoreBadge score={f.risk_score} size="lg" />
          <div>
            <h2>{f.title}</h2>
            <div className="row gap-s wrap">
              <TypePill type={f.scan_type} />
              <span className="muted small">
                {f.tool} · {f.rule_id}
              </span>
              {f.in_kev && <Pill tone="kev">CISA KEV</Pill>}
              <Pill>{f.status.replace('_', ' ')}</Pill>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>

        <section>
          <h3>Why this score</h3>
          <div className="score-math">
            <span>
              Base <b>{f.base_score.toFixed(1)}</b>
            </span>
            <span>
              AI {f.ai_adjustment >= 0 ? '+' : '−'} <b>{Math.abs(f.ai_adjustment).toFixed(1)}</b>
            </span>
            <span>
              = Risk <b>{f.risk_score.toFixed(1)}</b>
            </span>
          </div>
          <dl className="factors">
            {Object.entries(FACTOR_LABELS).map(([k, label]) =>
              f.score_factors[k] !== undefined ? (
                <div key={k}>
                  <dt>{label}</dt>
                  <dd>
                    {String(f.score_factors[k])}
                    {k === 'technical' && <span className="muted small"> ({String(f.score_factors.technical_source)})</span>}
                    {k === 'likelihood' && <span className="muted small"> ({String(f.score_factors.likelihood_source)})</span>}
                  </dd>
                </div>
              ) : null,
            )}
          </dl>
          {f.ai_rationale && (
            <div className="ai-note">
              <b>AI assessment:</b> {f.ai_rationale}
            </div>
          )}
          {f.sla_days && <p className="muted small">Suggested remediation SLA: {f.sla_days} days</p>}
        </section>

        <section>
          <h3>Details</h3>
          <dl className="kv">
            {f.cve && (
              <>
                <dt>CVE</dt>
                <dd>
                  <a href={`https://nvd.nist.gov/vuln/detail/${f.cve}`} target="_blank" rel="noreferrer">
                    {f.cve}
                  </a>
                </dd>
              </>
            )}
            {f.cvss_score != null && (
              <>
                <dt>CVSS</dt>
                <dd>{f.cvss_score}</dd>
              </>
            )}
            {f.epss_score != null && (
              <>
                <dt>EPSS</dt>
                <dd>
                  {(f.epss_score * 100).toFixed(2)}% (percentile {((f.epss_percentile ?? 0) * 100).toFixed(0)})
                </dd>
              </>
            )}
            {f.cwe.length > 0 && (
              <>
                <dt>CWE</dt>
                <dd>{f.cwe.join(', ')}</dd>
              </>
            )}
            {f.package && (
              <>
                <dt>Package</dt>
                <dd className="mono">
                  {f.package}@{f.installed_version} → {f.fixed_version || 'no fix yet'}
                </dd>
              </>
            )}
            {f.file_path && (
              <>
                <dt>Location</dt>
                <dd className="mono">
                  {f.file_path}
                  {f.line ? `:${f.line}` : ''}
                </dd>
              </>
            )}
            {f.url && (
              <>
                <dt>URL</dt>
                <dd className="mono break">{f.url}</dd>
              </>
            )}
            <dt>Tool severity</dt>
            <dd>{f.severity}</dd>
            <dt>First seen</dt>
            <dd>{new Date(f.first_seen).toLocaleString()}</dd>
            <dt>Last seen</dt>
            <dd>{new Date(f.last_seen).toLocaleString()}</dd>
          </dl>
          {f.description && <p className="desc">{f.description}</p>}
        </section>

        <section>
          <h3>Triage</h3>
          <div className="row gap-s wrap">
            {f.status !== 'open' && (
              <button disabled={busy} onClick={() => setStatus('open')}>
                Reopen
              </button>
            )}
            {f.status === 'open' && (
              <>
                <button disabled={busy} onClick={() => setStatus('accepted')}>
                  Accept risk
                </button>
                <button disabled={busy} onClick={() => setStatus('false_positive')}>
                  False positive
                </button>
              </>
            )}
          </div>
          <ErrorNote error={error} />
        </section>
      </aside>
    </div>
  )
}
