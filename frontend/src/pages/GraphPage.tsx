import React from 'react'
import { useParams } from 'react-router-dom'
import { api, GraphOut } from '../api'

const TYPE_COLORS: Record<string, string> = {
  domain: '#58a6ff', subdomain: '#79c0ff', ip: '#f778ba',
  url: '#a371f7', port: '#d29922', technology: '#3fb950', external: '#8b949e',
}

/** Deterministic circular layout grouped by node type. */
function layout(nodes: GraphOut['nodes']) {
  const byType = new Map<string, GraphOut['nodes']>()
  for (const n of nodes) {
    if (!byType.has(n.node_type)) byType.set(n.node_type, [])
    byType.get(n.node_type)!.push(n)
  }
  const types = [...byType.keys()]
  const pos = new Map<string, { x: number; y: number }>()
  const R = 320
  types.forEach((t, ti) => {
    const group = byType.get(t)!
    const gr = 60 + (ti / Math.max(types.length, 1)) * (R - 120) + 90
    const angleBase = (2 * Math.PI * ti) / types.length
    group.forEach((n, i) => {
      const a = angleBase + (i / Math.max(group.length, 1)) * (Math.PI / types.length)
      pos.set(n.id, {
        x: 480 + gr * Math.cos(a),
        y: 360 + gr * Math.sin(a),
      })
    })
  })
  return pos
}

export default function GraphPage() {
  const { projectId = '' } = useParams()
  const [graph, setGraph] = React.useState<GraphOut | null>(null)
  React.useEffect(() => {
    api.graph(projectId).then(setGraph).catch(console.error)
  }, [projectId])

  if (!graph) return <div className="page"><p className="muted">Loading graph…</p></div>

  const pos = layout(graph.nodes)
  return (
    <div className="page">
      <h1>Attack surface graph</h1>
      <p className="muted">
        Generated from normalized data + correlation relationships.
        {graph.nodes.length} nodes, {graph.edges.length} edges.
      </p>
      <div className="legend">
        {Object.entries(TYPE_COLORS).map(([t, c]) => (
          <span key={t}><i className="dot" style={{ background: c }} />{t}</span>
        ))}
      </div>
      <svg id="graph" width="100%" height="640" viewBox="0 0 960 720">
        {graph.edges.map((e, i) => {
          const a = pos.get(e.src); const b = pos.get(e.dst)
          if (!a || !b) return null
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} />
        })}
        {graph.nodes.map(n => {
          const p = pos.get(n.id)
          if (!p) return null
          const color = TYPE_COLORS[n.node_type] ?? '#8b949e'
          return (
            <g key={n.id}>
              <circle cx={p.x} cy={p.y} r={5 + Math.min(8, n.score / 12)}
                      fill={color}
                      stroke={n.scope_status === 'OUT_OF_SCOPE' ? '#f85149' : 'transparent'}
                      strokeWidth={2}>
                <title>{`${n.label} (${n.node_type}, ${n.scope_status}, priority ${n.score})`}</title>
              </circle>
              <text x={p.x + 9} y={p.y + 4}>{n.label.slice(0, 28)}</text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
