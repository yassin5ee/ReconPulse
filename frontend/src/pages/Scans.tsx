import React from 'react'
import { useParams } from 'react-router-dom'
import { api, Scan } from '../api'

export default function Scans() {
  const { projectId = '' } = useParams()
  const [scans, setScans] = React.useState<Scan[]>([])
  const [profile, setProfile] = React.useState('standard')

  const load = React.useCallback(() => {
    api.listScans(projectId).then(setScans).catch(console.error)
  }, [projectId])
  React.useEffect(() => {
    load()
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [load])

  const start = async () => { try { await api.startScan(projectId, profile); load() } catch (e) { console.error(e) } }
  const stop = async (id: string) => { try { await api.stopScan(id); load() } catch (e) { console.error(e) } }

  const prev = (i: number): Scan | undefined => scans[i + 1]

  return (
    <div className="page">
      <h1>Scan history</h1>
      <div className="row">
        <select value={profile} onChange={e => setProfile(e.target.value)}>
          <option value="quick">quick</option>
          <option value="standard">standard</option>
          <option value="full">full</option>
        </select>
        <button onClick={start}>Start scan</button>
      </div>

      <table>
        <thead><tr>
          <th>Status</th><th>Profile</th><th>Started</th><th>Finished</th>
          <th>Hostnames</th><th>New / Removed vs previous</th><th></th>
        </tr></thead>
        <tbody>
          {scans.map((s, i) => {
            const diff = s.stats?.diff_vs_previous
            return (
              <tr key={s.id}>
                <td><span className={`badge ${s.status}`}>{s.status}</span>{s.error ? ' ⚠' : ''}</td>
                <td>{s.profile}</td>
                <td className="muted">{s.started_at ?? '–'}</td>
                <td className="muted">{s.finished_at ?? '–'}</td>
                <td>{s.stats?.hostname_count ?? '–'}</td>
                <td>
                  {diff && <>
                    <span style={{ color: 'var(--green)' }}>+{diff.added.length} new</span>{' '}
                    <span style={{ color: 'var(--red)' }}>−{diff.removed.length} removed</span>
                    {diff.added.length > 0 &&
                      <div className="reasons">new: {diff.added.slice(0, 8).join(', ')}{diff.added.length > 8 ? '…' : ''}</div>}
                  </>}
                  {(!prev(i) || !diff) && <span className="muted">—</span>}
                </td>
                <td>
                  {(s.status === 'running' || s.status === 'queued') &&
                    <button className="danger" onClick={() => stop(s.id)}>Stop</button>}
                </td>
              </tr>
            )
          })}
          {!scans.length && <tr><td colSpan={7} className="muted">No scans yet.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}
