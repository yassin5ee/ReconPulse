import React from 'react'
import ReactDOM from 'react-dom/client'
import { createBrowserRouter, RouterProvider, Outlet, NavLink, useParams, useNavigate } from 'react-router-dom'
import './styles.css'
import { api } from './api'
import Dashboard from './pages/Dashboard'
import Assets from './pages/Assets'
import Scans from './pages/Scans'
import GraphPage from './pages/GraphPage'
import Settings from './pages/Settings'

function ProjectLayout() {
  const { projectId } = useParams()
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">Recon<span>Pulse</span></div>
        <nav>
          <NavLink to={`/p/${projectId}`} end>Dashboard</NavLink>
          <NavLink to={`/p/${projectId}/assets`}>Assets</NavLink>
          <NavLink to={`/p/${projectId}/scans`}>Scans</NavLink>
          <NavLink to={`/p/${projectId}/graph`}>Attack Surface</NavLink>
          <NavLink to={`/p/${projectId}/settings`}>Settings</NavLink>
        </nav>
        <a className="back" href="/">← Projects</a>
      </aside>
      <main><Outlet /></main>
    </div>
  )
}

function Projects() {
  const [projects, setProjects] = React.useState<Awaited<ReturnType<typeof api.listProjects>>>([])
  const [name, setName] = React.useState('')
  const nav = useNavigate()
  React.useEffect(() => { api.listProjects().then(setProjects).catch(console.error) }, [])
  const create = async () => {
    if (!name.trim()) return
    const p = await api.createProject(name.trim())
    setName('')
    nav(`/p/${p.id}`)
  }
  return (
    <div className="page">
      <h1>Projects</h1>
      <p className="muted">
        ReconPulse is for <b>authorized</b> reconnaissance only. Only add targets
        you have explicit permission to test.
      </p>
      <div className="row">
        <input placeholder="New project name" value={name}
               onChange={e => setName(e.target.value)}
               onKeyDown={e => e.key === 'Enter' && create()} />
        <button onClick={create}>Create project</button>
      </div>
      <table>
        <thead><tr><th>Name</th><th>Description</th><th></th></tr></thead>
        <tbody>
          {projects.map(p => (
            <tr key={p.id} onClick={() => nav(`/p/${p.id}`)} className="clickable">
              <td>{p.name}</td><td>{p.description}</td><td>→</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const router = createBrowserRouter([
  { path: '/', element: <Projects /> },
  {
    path: '/p/:projectId',
    element: <ProjectLayout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'assets', element: <Assets /> },
      { path: 'scans', element: <Scans /> },
      { path: 'graph', element: <GraphPage /> },
      { path: 'settings', element: <Settings /> },
    ],
  },
])

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode><RouterProvider router={router} /></React.StrictMode>,
)
