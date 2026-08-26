import React from 'react'
import { useParams } from 'react-router-dom'
import { api, Asset } from '../api'

const TYPES = ['', 'subdomain', 'domain', 'ip', 'url']

export default function Assets() {
  const { projectId = '' } = useParams()
  const [assets, setAssets] = React.useState<Asset[]>([])
  const [type, setType] = React.useState('')
  const [search, setSearch] = React.useState('')
  const [minScore, setMinScore] = React.useState(0)

  const load = React.useCallback(() => {
    const params: Record<string, string> = { min_score: String(minScore) }
    if (type) params.asset_type = type
    if (search) params.search = search
    api.listAssets(projectId, params).then(setAssets).catch(console.error)
  }, [projectId, type, search, minScore])
  React.useEffect(() => { load() }, [load])

  return (
    <div className="page">
      <h1>Assets</h1>
      <div className="row">
        <select value={type} onChange={e => setType(e.target.value)}>
          {TYPES.map(t => <option key={t} value={t}>{t || 'all types'}</option>)}
        </select>
        <input placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)} />
        <label className="muted">min score
          <input type="number" min={0} max={100} value={minScore} style={{ width: 80 }}
                 onChange={e => setMinScore(Number(e.target.value))} />
        </label>
        <button className="secondary" onClick={load}>Refresh</button>
        <a href={api.reportUrl(projectId, 'csv')}><button className="secondary">Export CSV</button></a>
        <a href={api.reportUrl(projectId, 'json')}><button className="secondary">Export JSON</button></a>
      </div>

      <table>
        <thead><tr><th>Value</th><th>Type</th><th>Scope</th><th>Priority</th><th>Title / Status</th></tr></thead>
        <tbody>
          {assets.map(a => (
            <tr key={a.id}>
              <td>{a.value}</td>
              <td>{a.asset_type}</td>
              <td><span className={`badge ${a.scope_status}`}>{a.scope_status}</span></td>
              <td>
                <span className="scorebar"><i style={{ width: `${a.priority_score}%` }} /></span> {a.priority_score}
                <div className="reasons">{(a.priority_reasons ?? []).map((r: any) => r.reason).join(', ')}</div>
              </td>
              <td className="muted">
                {(a.extra_data as any)?.title ? `${(a.extra_data as any).title} ` : ''}
                {(a.extra_data as any)?.status_code ? `(${(a.extra_data as any).status_code})` : ''}
              </td>
            </tr>
          ))}
          {!assets.length && <tr><td colSpan={5} className="muted">No assets match.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}
