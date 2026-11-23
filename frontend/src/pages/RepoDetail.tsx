import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, timeAgo, type Repo } from '../api'
import { FindingsTable } from '../components/FindingsTable'
import { Empty, ErrorNote, ScoreBadge, TypePill } from '../components/ui'
import { useAsync } from '../components/useAsync'

export function RepoDetailPage() {
  const id = Number(useParams().id)
  const repo = useAsync(() => api.repo(id), [id])
  const findings = useAsync(() => api.findings({ repo_id: id }), [id])
  const scans = useAsync(() => api.scans(id), [id])
  const [analyzing, setAnalyzing] = useState(false)
  const [aiError, setAiError] = useState<unknown>(null)

  if (repo.error) return <ErrorNote error={repo.error} />
  if (!repo.data) return <div className="muted">Loading…</div>
  const r = repo.data

  async function analyze() {
    setAnalyzing(true)
    setAiError(null)
    try {
      await api.analyze(id)
      await Promise.all([repo.reload(), findings.reload()])
    } catch (e) {
      setAiError(e)
    } finally {
      setAnalyzing(false)
    }
  }

  return (
    <div className="stack">
      <div className="row gap-m">
        <Link to="/" className="small">
          ← Portfolio
        </Link>
      </div>
      <div className="repo-head">
        <ScoreBadge score={r.risk_score} size="lg" />
        <div>
          <h1>{r.full_name}</h1>
          <div className="muted">{r.description || 'No description yet. Add business context below.'}</div>
        </div>
      </div>

      <div className="grid-2">
        <ContextForm
          repo={r}
          onSaved={(updated) => {
            repo.setData(updated)
            findings.reload()
          }}
        />
        <div className="card">
          <div className="row between">
            <h2>AI risk assessment</h2>
            <button onClick={analyze} disabled={analyzing}>
              {analyzing ? 'Analyzing…' : r.ai_summary ? 'Re-run' : 'Run analysis'}
            </button>
          </div>
          {r.ai_summary ? (
            <>
              <p className="ai-summary">{r.ai_summary}</p>
              <div className="muted small">Updated {timeAgo(r.ai_summary_at)}</div>
            </>
          ) : (
            <p className="muted">
              Claude reviews the top open findings against this repository's business context, adjusts each score by up to ±15
              points with a written reason, and drafts a prioritized remediation plan.
            </p>
          )}
          <ErrorNote error={aiError} />
        </div>
      </div>

      <div className="card">
        <h2>Open findings</h2>
        <ErrorNote error={findings.error} />
        {findings.data?.length === 0 && <Empty title="No open findings" />}
        {findings.data && findings.data.length > 0 && (
          <FindingsTable findings={findings.data} showRepo={false} onChange={() => (findings.reload(), repo.reload())} />
        )}
      </div>

      <div className="card">
        <h2>Recent scans</h2>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Type</th>
                <th>Tool</th>
                <th>Branch / commit</th>
                <th className="num">Findings</th>
                <th className="num">New</th>
                <th className="num">Fixed</th>
              </tr>
            </thead>
            <tbody>
              {scans.data?.map((s) => (
                <tr key={s.id}>
                  <td className="small">
                    {s.workflow_run_url ? (
                      <a href={s.workflow_run_url} target="_blank" rel="noreferrer">
                        {timeAgo(s.created_at)}
                      </a>
                    ) : (
                      timeAgo(s.created_at)
                    )}
                  </td>
                  <td>
                    <TypePill type={s.scan_type} />
                  </td>
                  <td className="small">{s.tool}</td>
                  <td className="mono small">
                    {s.branch ?? '—'} {s.commit_sha?.slice(0, 7)}
                  </td>
                  <td className="num">{s.finding_count}</td>
                  <td className="num">{s.new_count}</td>
                  <td className="num">{s.fixed_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function ContextForm({ repo, onSaved }: { repo: Repo; onSaved: (r: Repo) => void }) {
  const [form, setForm] = useState({ ...repo, compliance_text: repo.compliance.join(', ') })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm({ ...form, [k]: v })

  async function save(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    try {
      const updated = await api.updateRepo(repo.id, {
        description: form.description || null,
        business_unit: form.business_unit || null,
        owner: form.owner || null,
        default_branch: form.default_branch,
        criticality: form.criticality,
        exposure: form.exposure,
        data_sensitivity: form.data_sensitivity,
        revenue_impacting: form.revenue_impacting,
        compliance: form.compliance_text
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      })
      onSaved(updated)
      setError(null)
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <form className="card form" onSubmit={save}>
      <h2>Business context</h2>
      <label>
        What it does
        <textarea rows={2} value={form.description ?? ''} onChange={(e) => set('description', e.target.value)} />
      </label>
      <div className="grid-form">
        <label>
          Business unit
          <input value={form.business_unit ?? ''} onChange={(e) => set('business_unit', e.target.value)} />
        </label>
        <label>
          Owner
          <input value={form.owner ?? ''} onChange={(e) => set('owner', e.target.value)} />
        </label>
        <label>
          Criticality
          <select value={form.criticality} onChange={(e) => set('criticality', Number(e.target.value))}>
            <option value={1}>1 · Low</option>
            <option value={2}>2</option>
            <option value={3}>3 · Moderate</option>
            <option value={4}>4</option>
            <option value={5}>5 · Crown jewel</option>
          </select>
        </label>
        <label>
          Exposure
          <select value={form.exposure} onChange={(e) => set('exposure', e.target.value as Repo['exposure'])}>
            <option value="internal">Internal only</option>
            <option value="partner">Partner / B2B</option>
            <option value="internet">Internet-facing</option>
          </select>
        </label>
        <label>
          Data sensitivity
          <select
            value={form.data_sensitivity}
            onChange={(e) => set('data_sensitivity', e.target.value as Repo['data_sensitivity'])}
          >
            <option value="public">Public</option>
            <option value="internal">Internal</option>
            <option value="confidential">Confidential</option>
            <option value="restricted">Restricted (PII/PCI/PHI)</option>
          </select>
        </label>
        <label>
          Compliance scope
          <input
            placeholder="PCI, SOC2, HIPAA"
            value={form.compliance_text}
            onChange={(e) => set('compliance_text', e.target.value)}
          />
        </label>
        <label>
          Default branch
          <input value={form.default_branch} onChange={(e) => set('default_branch', e.target.value)} />
        </label>
        <label className="row gap-s check">
          <input
            type="checkbox"
            checked={form.revenue_impacting}
            onChange={(e) => set('revenue_impacting', e.target.checked)}
          />
          Revenue-impacting
        </label>
      </div>
      <div className="row gap-s">
        <button type="submit" className="primary" disabled={saving}>
          {saving ? 'Saving…' : 'Save and rescore'}
        </button>
      </div>
      <ErrorNote error={error} />
    </form>
  )
}
