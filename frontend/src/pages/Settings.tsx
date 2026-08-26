import React from 'react'
import { useParams } from 'react-router-dom'
import { api, Project, ScopeRule, Target } from '../api'

export default function Settings() {
  const { projectId = '' } = useParams()
  const [project, setProject] = React.useState<Project | null>(null)
  const [targets, setTargets] = React.useState<Target[]>([])
  const [rules, setRules] = React.useState<ScopeRule[]>([])
  const [targetInput, setTargetInput] = React.useState('')
  const [pattern, setPattern] = React.useState('')
  const [ruleType, setRuleType] = React.useState('DENY')
  const [error, setError] = React.useState('')

  const load = React.useCallback(() => {
    api.getProject(projectId).then(setProject).catch(console.error)
    api.listTargets(projectId).then(setTargets).catch(console.error)
    api.listScope(projectId).then(setRules).catch(console.error)
  }, [projectId])
  React.useEffect(() => { load() }, [load])

  const addTarget = async () => {
    setError('')
    try {
      await api.addTargets(projectId, [{ value: targetInput.trim(), target_type: 'domain' }])
      setTargetInput(''); load()
    } catch (e: any) { setError(String(e.message ?? e)) }
  }
  const addRule = async () => {
    setError('')
    try {
      await api.addScopeRules(projectId, [{ pattern: pattern.trim(), rule_type: ruleType }])
      setPattern(''); load()
    } catch (e: any) { setError(String(e.message ?? e)) }
  }

  if (!project) return <div className="page"><p className="muted">Loading…</p></div>

  return (
    <div className="page">
      <h1>{project.name} — settings</h1>
      <p className="muted">{project.description}</p>
      {error && <p style={{ color: 'var(--red)' }}>{error}</p>}

      <h2>Authorized targets</h2>
      <div className="row">
        <input placeholder="example.com" value={targetInput}
               onChange={e => setTargetInput(e.target.value)} />
        <button onClick={addTarget}>Add target</button>
      </div>
      <table><tbody>
        {targets.map(t => <tr key={t.id}><td>{t.value}</td><td>{t.target_type}</td></tr>)}
      </tbody></table>

      <h2>Scope rules</h2>
      <p className="muted">DENY always wins. Only IN_SCOPE assets are actively scanned.</p>
      <div className="row">
        <input placeholder="*.staging.example.com or 10.0.0.0/8" value={pattern}
               onChange={e => setPattern(e.target.value)} />
        <select value={ruleType} onChange={e => setRuleType(e.target.value)}>
          <option value="ALLOW">ALLOW</option>
          <option value="DENY">DENY</option>
        </select>
        <button onClick={addRule}>Add rule</button>
      </div>
      <table><thead><tr><th>Pattern</th><th>Type</th><th>Comment</th></tr></thead>
        <tbody>
          {rules.map(r => (
            <tr key={r.id}>
              <td>{r.pattern}</td>
              <td><span className={`badge ${r.rule_type}`}>{r.rule_type}</span></td>
              <td className="muted">{r.comment}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
