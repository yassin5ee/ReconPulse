import React from 'react'
import { useParams, Link } from 'react-router-dom'
import { api, Scan, Statistics } from '../api'

export default function Dashboard() {
  const { projectId = '' } = useParams()
  const [stats, setStats] = React.useState<Statistics | null>(null)
  const [scans, setScans] = React.useState<Scan[]>([])
  const [high, setHigh] = React.useState<Record<string, any>[]>([])
  const [profile, setProfile] = React.useState('standard')
  const [error, setError] = React.useState('')

  const load = React.useCallback(() => {
    api.statistics(projectId).then(setStats).catch(console.error)
    api.listScans(projectId).then(s => setScans(s.slice(0, 5))).catch(console.error)
    api.listAssets(projectId, { min_score: '40' }).then(setHigh).catch(console.error)
  }, [projectId])
  React.useEffect(() => { load() }, [load])

  const startScan = async () => {
    setError('')
    try {
      await api.startScan(projectId, profile)
      load()
    } catch (e: any) { setError(String(e.message ?? e)) }
  }

  if (!stats) return <div className="page"><p className="muted">Loading…</p></div>

  const cards: [string, number | string][] = [
    ['Assets', stats.assets], ['Domains', stats.domains], ['Subdomains', stats.subdomains],
    ['IPs', stats.ips], ['URLs', stats.urls], ['Open ports', stats.open_ports],
    ['Technologies', stats.technologies], ['High priority', stats.high_priority_assets],
  ]

  return (
    <div className="page">
      <div className="row" style={{ alignItems: 'center' }}>
        <select value={profile} onChange={e => setProfile(e.target.value)}>
          <option value="quick">quick (passive)</option>
          <option value="standard">standard</option>
          <option value="full">full</option>
        </select>
        <button onClick={startScan}>Start scan</button>
        <a href={api.reportUrl(projectId, 'html')} target="_blank" rel="noreferrer">
          <button className="secondary">HTML report</button>
        </a>
        {stats.last_scan_status &&
          <span className={`badge ${stats.last_scan_status}`}>last scan: {stats.last_scan_status}</span>}
        <span className="muted">{scans.length ? `${scans[0].stats?.hostname_count ?? '–'} hostnames (latest)` : ''}</span>
      </div>
      {error && <p style={{ color: 'var(--red)' }}>{error}</p>}

      <div className="cards">
        {cards.map(([label, num]) => (
          <div key={label} className="card">
            <div className="num">{num}</div><div className="label">{label}</div>
          </div>
        ))}
      </div>

      <h2>Priority queue — investigate first</h2>
      <table>
        <thead><tr><th>Asset</th><th>Type</th><th>Scope</th><th>Score</th><th>Why</th></tr></thead>
        <tbody>
          {high.map(a => (
            <tr key={a.id}>
              <td>{a.value}</td>
              <td>{a.asset_type}</td>
              <td><span className={`badge ${a.scope_status}`}>{a.scope_status}</span></td>
              <td><span className="scorebar"><i style={{ width: `${a.priority_score}%` }} /></span> {a.priority_score}</td>
              <td className="reasons">
                {(a.priority_reasons ?? []).map((r: any) => r.reason).join(', ') || '—'}
              </td>
            </tr>
          ))}
          {!high.length && <tr><td colSpan={5} className="muted">Run a scan to populate the attack surface.</td></tr>}
        </tbody>
      </table>

      <h2>Recent scans</h2>
      <table>
        <thead><tr><th>Status</th><th>Profile</th><th>Hostnames</th><th>Started</th></tr></thead>
        <tbody>
          {scans.map(s => (
            <tr key={s.id}>
              <td><span className={`badge ${s.status}`}>{s.status}</span></td>
              <td>{s.profile}</td>
              <td>{s.stats?.hostname_count ?? '–'}</td>
              <td className="muted">{s.started_at ?? 'queued'}</td>
            </tr>
          ))}
          {!scans.length && <tr><td colSpan={4} className="muted">No scans yet.</td></tr>}
        </tbody>
      </table>
      <p><Link to={`/p/${projectId}/scans`}>Full scan history →</Link></p>
    </div>
  )
}
