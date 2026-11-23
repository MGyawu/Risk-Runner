import { useState } from 'react'
import { api, type FindingQuery } from '../api'
import { FindingsTable } from '../components/FindingsTable'
import { Empty, ErrorNote } from '../components/ui'
import { useAsync } from '../components/useAsync'

export function FindingsPage() {
  const [query, setQuery] = useState<FindingQuery>({ status: 'open' })
  const [search, setSearch] = useState('')
  const res = useAsync(() => api.findings(query), [JSON.stringify(query)])

  return (
    <div className="stack">
      <div className="card filters">
        <form
          className="row gap-s wrap"
          onSubmit={(e) => {
            e.preventDefault()
            setQuery({ ...query, q: search || undefined })
          }}
        >
          <input
            type="search"
            placeholder="Search title, CVE, package, path"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search findings"
          />
          <select
            value={query.scan_type ?? ''}
            onChange={(e) => setQuery({ ...query, scan_type: e.target.value as FindingQuery['scan_type'] })}
            aria-label="Scan type"
          >
            <option value="">All types</option>
            <option value="sast">SAST</option>
            <option value="sca">SCA</option>
            <option value="dast">DAST</option>
          </select>
          <select
            value={query.status ?? ''}
            onChange={(e) => setQuery({ ...query, status: e.target.value as FindingQuery['status'] })}
            aria-label="Status"
          >
            <option value="open">Open</option>
            <option value="fixed">Fixed</option>
            <option value="accepted">Risk accepted</option>
            <option value="false_positive">False positive</option>
            <option value="">Any status</option>
          </select>
          <select
            value={String(query.min_score ?? 0)}
            onChange={(e) => setQuery({ ...query, min_score: Number(e.target.value) || undefined })}
            aria-label="Minimum risk"
          >
            <option value="0">Any risk</option>
            <option value="40">Medium+ (40)</option>
            <option value="65">High+ (65)</option>
            <option value="85">Critical (85)</option>
          </select>
          <label className="row gap-s small">
            <input
              type="checkbox"
              checked={!!query.kev}
              onChange={(e) => setQuery({ ...query, kev: e.target.checked || undefined })}
            />
            KEV only
          </label>
          <button type="submit">Search</button>
        </form>
      </div>
      <ErrorNote error={res.error} />
      {res.data && res.data.length === 0 && <Empty title="No findings match these filters" />}
      {res.data && res.data.length > 0 && (
        <div className="card">
          <FindingsTable findings={res.data} onChange={() => res.reload()} />
        </div>
      )}
    </div>
  )
}
