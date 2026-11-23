import { Link } from 'react-router-dom'
import { api, timeAgo } from '../api'
import { FindingsTable } from '../components/FindingsTable'
import { BandBar, Empty, ErrorNote, ScoreBadge, Stat, TrendChart, TypePill } from '../components/ui'
import { useAsync } from '../components/useAsync'

export function OverviewPage() {
  const ov = useAsync(() => api.overview(), [])
  const repos = useAsync(() => api.repos(), [])
  const error = ov.error || repos.error

  if (error) return <ErrorNote error={error} />
  if (!ov.data || !repos.data) return <div className="muted">Loading…</div>
  const o = ov.data

  if (o.repositories === 0) {
    return (
      <Empty title="No scans ingested yet">
        <p>
          Add the Risk Runner upload step to a GitHub Actions workflow to send SAST, SCA and DAST results here. See{' '}
          <code>examples/security-scan.yml</code> in the Risk Runner repository.
        </p>
      </Empty>
    )
  }

  const last = o.trend[o.trend.length - 1]?.open ?? 0
  const first = o.trend[0]?.open ?? 0

  return (
    <div className="stack">
      <div className="stats">
        <Stat label="Highest repo risk" value={<ScoreBadge score={o.portfolio_risk} size="lg" />} hint="Worst repository in the portfolio" />
        <Stat label="Open findings" value={o.open_findings.toLocaleString()} hint={`${o.repositories} repositories`} />
        <Stat
          label="Known exploited (KEV)"
          value={o.kev_findings}
          hint="Open findings on CISA's KEV list"
          tone={o.kev_findings ? 'alert' : undefined}
        />
        <Stat
          label="Critical + high risk"
          value={o.by_band.critical + o.by_band.high}
          hint="Business-adjusted, not tool severity"
        />
      </div>

      <div className="grid-2">
        <div className="card">
          <h2>Risk distribution</h2>
          <BandBar counts={o.by_band} showLegend />
          <div className="row gap-m wrap" style={{ marginTop: 16 }}>
            {(['sast', 'sca', 'dast'] as const).map((t) => (
              <span key={t} className="row gap-s">
                <TypePill type={t} /> <b>{o.by_type[t] ?? 0}</b>
              </span>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="row between">
            <h2>Open findings, 30 days</h2>
            <span className={`small ${last > first ? 'up' : 'down'}`}>
              {last - first >= 0 ? '+' : ''}
              {last - first}
            </span>
          </div>
          <TrendChart data={o.trend} />
        </div>
      </div>

      <div className="card">
        <h2>Repositories by business risk</h2>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th className="num">Risk</th>
                <th>Repository</th>
                <th>Context</th>
                <th className="wide">Open findings by risk</th>
                <th className="num">KEV</th>
                <th>Last scan</th>
              </tr>
            </thead>
            <tbody>
              {repos.data.map((r) => (
                <tr key={r.id}>
                  <td className="num">
                    <ScoreBadge score={r.risk_score} />
                  </td>
                  <td>
                    <Link to={`/repos/${r.id}`}>{r.full_name}</Link>
                    <div className="muted small">{r.business_unit ?? 'Unassigned'}</div>
                  </td>
                  <td className="small">
                    <div>Criticality {r.criticality}/5</div>
                    <div className="muted">
                      {r.exposure} · {r.data_sensitivity}
                    </div>
                  </td>
                  <td>
                    <BandBar counts={r.by_band} />
                    <div className="muted small">{r.open_findings} open</div>
                  </td>
                  <td className="num">{r.kev_findings || '—'}</td>
                  <td className="small muted">{timeAgo(r.last_scan_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="row between">
          <h2>Top risks across the portfolio</h2>
          <Link to="/findings">All findings →</Link>
        </div>
        <FindingsTable findings={o.top_findings} onChange={() => ov.reload()} />
      </div>
    </div>
  )
}
