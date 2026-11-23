import type { ReactNode } from 'react'
import { BANDS, band, type BandCounts, type ScanType } from '../api'

export function ScoreBadge({ score, size = 'md' }: { score: number; size?: 'md' | 'lg' }) {
  const b = band(score)
  return (
    <span className={`score score-${b} score-${size}`} title={`Risk ${score.toFixed(1)} (${b})`}>
      {Math.round(score)}
    </span>
  )
}

export function Pill({ children, tone = 'neutral' }: { children: ReactNode; tone?: string }) {
  return <span className={`pill pill-${tone}`}>{children}</span>
}

const TYPE_LABEL: Record<ScanType, string> = { sast: 'SAST', sca: 'SCA', dast: 'DAST' }
export function TypePill({ type }: { type: ScanType }) {
  return <Pill tone={type}>{TYPE_LABEL[type]}</Pill>
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: string; tone?: string }) {
  return (
    <div className={`card stat ${tone ? `stat-${tone}` : ''}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  )
}

/** Horizontal stacked bar of risk bands. */
export function BandBar({ counts, showLegend = false }: { counts: BandCounts; showLegend?: boolean }) {
  const total = BANDS.reduce((n, b) => n + (counts[b] ?? 0), 0)
  return (
    <div>
      <div className="bandbar" role="img" aria-label={BANDS.map((b) => `${counts[b] ?? 0} ${b}`).join(', ')}>
        {total === 0 ? (
          <div className="bandbar-empty" />
        ) : (
          BANDS.filter((b) => counts[b]).map((b) => (
            <div key={b} className={`seg seg-${b}`} style={{ flexGrow: counts[b] }} title={`${counts[b]} ${b}`} />
          ))
        )}
      </div>
      {showLegend && (
        <div className="legend">
          {BANDS.map((b) => (
            <span key={b}>
              <i className={`dot seg-${b}`} />
              {b} <b>{counts[b] ?? 0}</b>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export function TrendChart({ data }: { data: { date: string; open: number }[] }) {
  if (!data.length) return null
  const w = 600
  const h = 140
  const pad = 4
  const max = Math.max(1, ...data.map((d) => d.open))
  const x = (i: number) => pad + (i * (w - 2 * pad)) / Math.max(1, data.length - 1)
  const y = (v: number) => h - pad - (v / max) * (h - 2 * pad - 16)
  const line = data.map((d, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(d.open).toFixed(1)}`).join(' ')
  const area = `${line} L${x(data.length - 1)},${h - pad} L${x(0)},${h - pad} Z`
  const last = data[data.length - 1]
  return (
    <svg className="trend" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" role="img" aria-label={`Open findings over 30 days, now ${last.open}`}>
      <path d={area} className="trend-area" />
      <path d={line} className="trend-line" vectorEffect="non-scaling-stroke" />
      <title>{`${data[0].date}: ${data[0].open} → ${last.date}: ${last.open}`}</title>
    </svg>
  )
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children}
    </div>
  )
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null
  return <div className="error">{error instanceof Error ? error.message : String(error)}</div>
}
