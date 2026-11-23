import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { Finding } from '../api'
import { FindingDrawer } from './FindingDrawer'
import { Pill, ScoreBadge, TypePill } from './ui'

function location(f: Finding) {
  if (f.package) return `${f.package}@${f.installed_version ?? '?'}`
  if (f.file_path) return `${f.file_path}${f.line ? `:${f.line}` : ''}`
  return f.url ?? ''
}

export function FindingsTable({
  findings,
  showRepo = true,
  onChange,
}: {
  findings: Finding[]
  showRepo?: boolean
  onChange?: (f: Finding) => void
}) {
  const [open, setOpen] = useState<Finding | null>(null)
  return (
    <>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th className="num">Risk</th>
              <th>Finding</th>
              {showRepo && <th>Repository</th>}
              <th>Type</th>
              <th>Signals</th>
              <th className="num">SLA</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} onClick={() => setOpen(f)} className="clickable">
                <td className="num">
                  <ScoreBadge score={f.risk_score} />
                </td>
                <td className="finding-cell">
                  <div className="finding-title">{f.title}</div>
                  <div className="muted mono small truncate">{location(f)}</div>
                </td>
                {showRepo && (
                  <td>
                    <Link to={`/repos/${f.repository_id}`} onClick={(e) => e.stopPropagation()}>
                      {f.repository_name}
                    </Link>
                  </td>
                )}
                <td>
                  <TypePill type={f.scan_type} />
                </td>
                <td className="signals">
                  {f.in_kev && <Pill tone="kev">KEV</Pill>}
                  {f.cve && <span className="mono small">{f.cve}</span>}
                  {f.epss_score != null && <span className="small muted">EPSS {(f.epss_score * 100).toFixed(1)}%</span>}
                  {f.ai_adjustment !== 0 && (
                    <Pill tone="ai">
                      AI {f.ai_adjustment > 0 ? '+' : ''}
                      {f.ai_adjustment.toFixed(0)}
                    </Pill>
                  )}
                  {f.status !== 'open' && <Pill>{f.status.replace('_', ' ')}</Pill>}
                </td>
                <td className="num small">{f.sla_days ? `${f.sla_days}d` : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {open && (
        <FindingDrawer
          finding={open}
          onClose={() => setOpen(null)}
          onChange={(f) => {
            setOpen(f)
            onChange?.(f)
          }}
        />
      )}
    </>
  )
}
