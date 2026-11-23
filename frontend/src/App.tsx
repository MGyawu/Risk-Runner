import { useState } from 'react'
import { NavLink, Route, Routes } from 'react-router-dom'
import { api, getToken, setToken } from './api'
import { FindingsPage } from './pages/Findings'
import { OverviewPage } from './pages/Overview'
import { RepoDetailPage } from './pages/RepoDetail'

export default function App() {
  const [refreshing, setRefreshing] = useState(false)

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <img src="/favicon.svg" alt="" width={24} height={24} />
          Risk Runner
        </div>
        <nav>
          <NavLink to="/" end>
            Portfolio
          </NavLink>
          <NavLink to="/findings">Findings</NavLink>
        </nav>
        <div className="row gap-s">
          <button
            className="ghost small"
            disabled={refreshing}
            title="Re-pull EPSS, CISA KEV and NVD data and rescore"
            onClick={async () => {
              setRefreshing(true)
              try {
                await api.refreshIntel()
              } finally {
                setTimeout(() => setRefreshing(false), 1500)
              }
            }}
          >
            {refreshing ? 'Refresh queued' : 'Refresh threat intel'}
          </button>
          <button
            className="ghost small"
            title="Set the API token used by this dashboard"
            onClick={() => {
              const t = window.prompt('API token (leave blank if the server has none)', getToken())
              if (t !== null) {
                setToken(t)
                window.location.reload()
              }
            }}
          >
            Token
          </button>
        </div>
      </header>
      <main className="content">
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/repos/:id" element={<RepoDetailPage />} />
        </Routes>
      </main>
    </div>
  )
}
