import { useState, useEffect } from 'react'
import { 
  ShieldAlert, Activity, Server, FileWarning, 
  TrendingUp, TrendingDown, LayoutDashboard, Shield,
  Settings, Bell, Search, Hexagon
} from 'lucide-react'
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar
} from 'recharts'
import './index.css'

// Mock Data (matches the FastAPI endpoints we built)
const mockTrendData = [
  { time: '00:00', blocked: 12, allowed: 45 },
  { time: '04:00', blocked: 8, allowed: 30 },
  { time: '08:00', blocked: 45, allowed: 120 },
  { time: '12:00', blocked: 65, allowed: 180 },
  { time: '16:00', blocked: 35, allowed: 150 },
  { time: '20:00', blocked: 18, allowed: 80 },
];

const mockRiskData = [
  { name: 'SEC-EXEC', count: 12 },
  { name: 'SEC-FS', count: 8 },
  { name: 'SEC-NET', count: 24 },
  { name: 'SEC-PROTO', count: 5 },
  { name: 'SEC-PRMPT', count: 15 },
];

const mockFindings = [
  { id: '1', rule: 'SEC-EXEC-001', severity: 'critical', tool: 'bash_eval', title: 'Arbitrary Command Execution' },
  { id: '2', rule: 'SEC-PRMPT-002', severity: 'high', tool: 'none', title: 'Sensitive Data in Prompt' },
  { id: '3', rule: 'SEC-FS-001', severity: 'high', tool: 'read_file', title: 'Arbitrary Filesystem Access' },
  { id: '4', rule: 'SEC-PROTO-008', severity: 'medium', tool: 'malformed_tool', title: 'Malformed Tool Schema' },
];

function App() {
  const [metrics, setMetrics] = useState({
    total_servers: 14,
    critical_findings: 3,
    blocked_requests_24h: 127,
    average_security_risk: 42.5
  });

  return (
    <div className="dashboard-container">
      
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="logo-container">
          <Hexagon className="logo-icon" size={32} />
          <span className="logo-text">MCP-Audit</span>
        </div>
        
        <nav>
          <a href="#" className="nav-item active">
            <LayoutDashboard size={20} />
            <span>Overview</span>
          </a>
          <a href="#" className="nav-item">
            <Server size={20} />
            <span>MCP Servers</span>
          </a>
          <a href="#" className="nav-item">
            <ShieldAlert size={20} />
            <span>Findings</span>
          </a>
          <a href="#" className="nav-item">
            <Activity size={20} />
            <span>Live Traffic</span>
          </a>
          <a href="#" className="nav-item" style={{marginTop: 'auto'}}>
            <Settings size={20} />
            <span>Policies</span>
          </a>
        </nav>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        
        {/* Top Header */}
        <header className="header animate-in">
          <div>
            <h1 className="page-title">Enterprise Control Plane</h1>
            <p style={{color: 'var(--text-muted)'}}>Acme Corp Security Overview</p>
          </div>
          
          <div style={{display: 'flex', gap: '16px'}}>
            <div className="glass-card" style={{padding: '8px 12px', display: 'flex', alignItems: 'center', gap: '8px'}}>
              <Search size={18} color="var(--text-muted)" />
              <input 
                type="text" 
                placeholder="Search resources..." 
                style={{background: 'transparent', border: 'none', color: 'white', outline: 'none'}}
              />
            </div>
            <button className="glass-card" style={{padding: '10px', cursor: 'pointer', border: 'none'}}>
              <Bell size={20} color="var(--text-muted)" />
            </button>
          </div>
        </header>

        {/* Top Metrics Cards */}
        <div className="metrics-grid animate-in delay-1">
          <div className="glass-card metric-card">
            <div className="metric-header">
              <span>Avg Security Risk</span>
              <Activity size={18} color="var(--accent-warning)" />
            </div>
            <div className="metric-value" style={{color: 'var(--accent-warning)'}}>
              {metrics.average_security_risk}
            </div>
            <div className="metric-trend trend-down">
              <TrendingDown size={14} /> <span>-4.2% from last week</span>
            </div>
          </div>
          
          <div className="glass-card metric-card">
            <div className="metric-header">
              <span>Blocked RPCs (24h)</span>
              <Shield size={18} color="var(--accent-primary)" />
            </div>
            <div className="metric-value">
              {metrics.blocked_requests_24h}
            </div>
            <div className="metric-trend trend-up">
              <TrendingUp size={14} /> <span>+12% spike detected</span>
            </div>
          </div>

          <div className="glass-card metric-card">
            <div className="metric-header">
              <span>Critical Findings</span>
              <FileWarning size={18} color="var(--accent-danger)" />
            </div>
            <div className="metric-value" style={{color: 'var(--accent-danger)'}}>
              {metrics.critical_findings}
            </div>
            <div className="metric-trend trend-down">
              <TrendingDown size={14} /> <span>-1 resolved</span>
            </div>
          </div>

          <div className="glass-card metric-card">
            <div className="metric-header">
              <span>Tracked Servers</span>
              <Server size={18} color="var(--accent-secondary)" />
            </div>
            <div className="metric-value">
              {metrics.total_servers}
            </div>
            <div className="metric-trend">
              <span style={{color: 'var(--text-muted)'}}>Active across 3 orgs</span>
            </div>
          </div>
        </div>

        {/* Charts Section */}
        <div className="charts-area animate-in delay-2">
          <div className="glass-card">
            <h3 className="chart-title">Gateway Interception Volume (24h)</h3>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={mockTrendData}>
                  <defs>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--accent-danger)" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="var(--accent-danger)" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--accent-primary)" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="var(--accent-primary)" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="time" stroke="var(--text-muted)" />
                  <YAxis stroke="var(--text-muted)" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px' }}
                  />
                  <Area type="monotone" dataKey="allowed" stroke="var(--accent-primary)" fillOpacity={1} fill="url(#colorAllowed)" />
                  <Area type="monotone" dataKey="blocked" stroke="var(--accent-danger)" fillOpacity={1} fill="url(#colorBlocked)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="glass-card">
            <h3 className="chart-title">Risks by Category</h3>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={mockRiskData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={12} />
                  <Tooltip 
                    cursor={{fill: 'rgba(255,255,255,0.05)'}}
                    contentStyle={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px' }}
                  />
                  <Bar dataKey="count" fill="var(--accent-secondary)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Findings Table */}
        <div className="glass-card animate-in delay-3">
          <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem'}}>
            <h3 className="chart-title" style={{margin: 0}}>Open Active Findings</h3>
            <button style={{
              background: 'transparent', border: '1px solid var(--accent-primary)', 
              color: 'var(--accent-primary)', padding: '6px 12px', borderRadius: '6px',
              cursor: 'pointer', fontWeight: 600
            }}>View All</button>
          </div>
          
          <table className="findings-table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Severity</th>
                <th>Target Tool</th>
                <th>Description</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {mockFindings.map((f) => (
                <tr key={f.id}>
                  <td style={{fontFamily: 'monospace'}}>{f.rule}</td>
                  <td><span className={`badge ${f.severity}`}>{f.severity}</span></td>
                  <td style={{color: 'var(--text-muted)'}}>{f.tool}</td>
                  <td style={{fontWeight: 500}}>{f.title}</td>
                  <td>
                    <button style={{
                      background: 'rgba(59, 130, 246, 0.2)', border: 'none',
                      color: 'var(--accent-primary)', padding: '4px 10px', borderRadius: '4px',
                      cursor: 'pointer', fontSize: '0.8rem'
                    }}>
                      Remediate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

      </main>
    </div>
  )
}

export default App
