import { useState, useEffect } from 'react'
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar
} from 'recharts'
import './index.css'

// Mock Data
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
  const [metrics] = useState({
    total_servers: 14,
    critical_findings: 3,
    blocked_requests_24h: 127,
    average_security_risk: 42.5
  });

  useEffect(() => {
    const video = document.querySelector('.footer__video') as HTMLVideoElement;
    if (!video) return;

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        video.removeAttribute('autoplay');
        video.pause();
        return;
    }

    if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const playPromise = video.play();
                    if (playPromise !== undefined) {
                        playPromise.catch(() => { /* Ignore rejection */ });
                    }
                } else {
                    video.pause();
                }
            });
        }, { threshold: 0.15 });
        observer.observe(video);
    }
  }, []);

  return (
    <div className="dashboard-layout">
      
      {/* DASHBOARD CONTENT */}
      <main className="dashboard-content">
        
        {/* Top Header */}
        <header className="header">
          <div>
            <h1 className="page-title">mcp-audit <span style={{fontSize: '1rem', color: 'var(--ink-soft)'}}>Enterprise Control Plane</span></h1>
            <p style={{color: 'var(--ink-soft)'}}>The secure route to AI agent deployment.</p>
          </div>
        </header>

        {/* Top Metrics Cards */}
        <div className="metrics-grid">
          <div className="vintage-card metric-card">
            <div className="metric-header">
              <span>Avg Security Risk</span>
            </div>
            <div className="metric-value">{metrics.average_security_risk}</div>
            <div style={{color: 'var(--ink-soft)', fontSize: '0.85rem'}}>-4.2% from last week</div>
          </div>
          
          <div className="vintage-card metric-card">
            <div className="metric-header">
              <span>Blocked RPCs (24h)</span>
            </div>
            <div className="metric-value">{metrics.blocked_requests_24h}</div>
            <div style={{color: 'var(--ink-soft)', fontSize: '0.85rem'}}>+12% spike detected</div>
          </div>

          <div className="vintage-card metric-card">
            <div className="metric-header">
              <span>Critical Findings</span>
            </div>
            <div className="metric-value">{metrics.critical_findings}</div>
            <div style={{color: 'var(--ink-soft)', fontSize: '0.85rem'}}>-1 resolved</div>
          </div>

          <div className="vintage-card metric-card">
            <div className="metric-header">
              <span>Tracked Servers</span>
            </div>
            <div className="metric-value">{metrics.total_servers}</div>
            <div style={{color: 'var(--ink-soft)', fontSize: '0.85rem'}}>Active across 3 orgs</div>
          </div>
        </div>

        {/* Charts Section */}
        <div className="charts-area">
          <div className="vintage-card">
            <h3 className="chart-title">Gateway Interception Volume (24h)</h3>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={mockTrendData}>
                  <defs>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--ink-soft)" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="var(--ink-soft)" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--ink-light)" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="var(--ink-light)" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                  <XAxis dataKey="time" stroke="var(--ink)" />
                  <YAxis stroke="var(--ink)" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'var(--paper-card)', border: '1px solid var(--ink)', borderRadius: '2px', color: 'var(--ink)' }}
                  />
                  <Area type="monotone" dataKey="allowed" stroke="var(--ink-light)" fillOpacity={1} fill="url(#colorAllowed)" />
                  <Area type="monotone" dataKey="blocked" stroke="var(--ink)" fillOpacity={1} fill="url(#colorBlocked)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="vintage-card">
            <h3 className="chart-title">Risks by Category</h3>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={mockRiskData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                  <XAxis dataKey="name" stroke="var(--ink)" fontSize={12} />
                  <Tooltip 
                    cursor={{fill: 'rgba(43, 58, 48, 0.05)'}}
                    contentStyle={{ backgroundColor: 'var(--paper-card)', border: '1px solid var(--ink)', borderRadius: '2px', color: 'var(--ink)' }}
                  />
                  <Bar dataKey="count" fill="var(--ink)" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Findings Table */}
        <div className="vintage-card">
          <div style={{display: 'flex', justifyContent: 'space-between'}}>
            <h3 className="chart-title" style={{margin: 0, border: 'none'}}>Open Active Findings</h3>
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
                  <td style={{fontFamily: 'monospace', color: 'var(--ink)'}}>{f.rule}</td>
                  <td><span className={`badge ${f.severity}`}>{f.severity}</span></td>
                  <td style={{color: 'var(--ink-soft)'}}>{f.tool}</td>
                  <td style={{fontWeight: 500, color: 'var(--ink)'}}>{f.title}</td>
                  <td>
                    <button style={{
                      background: 'transparent', border: '1px solid var(--ink)',
                      color: 'var(--ink)', padding: '6px 12px', borderRadius: '2px',
                      cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600
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

      {/* DEVELOPER INTEGRATION SECTION */}
      <section className="section" style={{ borderTop: '1px solid var(--ink)' }}>
          <h2 className="section-header">Developer Integration</h2>
          <p className="section-text">
              Built for engineers. Integrate MCP-Audit directly into your CI/CD pipelines and infrastructure as code.
          </p>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '24px' }}>
              
              <div className="card" style={{ border: 'none', padding: 0 }}>
                  <h3 style={{ fontSize: '18px', marginBottom: '12px' }}>1. CI/CD Pipeline (GitHub Actions)</h3>
                  <p style={{ marginBottom: '12px', color: 'var(--ink-soft)' }}>Prevent vulnerable MCP tools from being merged by adding our CLI to your pre-commit hooks or CI/CD pipelines.</p>
                  <div className="code-block" style={{ fontSize: '12px', padding: '16px', whiteSpace: 'pre-wrap' }}>
{`name: MCP Security Scan
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: pip install mcp-audit
      - run: mcp-audit scan ./mcp-servers/`}
                  </div>
              </div>

              <div className="card" style={{ border: 'none', padding: 0 }}>
                  <h3 style={{ fontSize: '18px', marginBottom: '12px' }}>2. Python Gateway Integration</h3>
                  <p style={{ marginBottom: '12px', color: 'var(--ink-soft)' }}>Programmatically instantiate the Gateway Proxy to wrap your existing MCP Server deployments in Python.</p>
                  <div className="code-block" style={{ fontSize: '12px', padding: '16px', whiteSpace: 'pre-wrap' }}>
{`from mcp_audit.gateway import SecurityGatewayProxy
from mcp_audit.gateway.forwarder import ForwardingEngine

proxy = SecurityGatewayProxy()
forwarder = ForwardingEngine("npx @modelcontextprotocol/server-postgres")

# Intercept and forward RPC requests natively
async def handle_request(rpc_req):
    if proxy.evaluate_request(rpc_req):
        return await forwarder.forward_request(rpc_req)`}
                  </div>
              </div>

          </div>
      </section>

      {/* MERIDIAN VINTAGE FOOTER */}
      <footer className="footer">
          <div className="footer__content">
              {/* Compass Logo */}
              <svg className="footer__mark" viewBox="0 0 64 64" role="img" aria-label="MCP-Audit compass">
                  <circle cx="32" cy="32" r="30" fill="none" stroke="currentColor" strokeWidth="2.2" />
                  <circle cx="32" cy="32" r="25.5" fill="none" stroke="currentColor" strokeWidth=".8" opacity=".5" />
                  <g fill="currentColor" opacity=".85">
                      <path d="M32 32 L46 18 L35.2 34.4 Z" />
                      <path d="M32 32 L46 46 L29.6 35.2 Z" />
                      <path d="M32 32 L18 46 L28.8 29.6 Z" />
                      <path d="M32 32 L18 18 L34.4 28.8 Z" />
                  </g>
                  <g stroke="currentColor" strokeWidth="1" strokeLinejoin="round">
                      <path d="M32 8 L35.5 28.5 L32 32 Z" fill="currentColor" />
                      <path d="M32 8 L28.5 28.5 L32 32 Z" fill="none" />
                      <path d="M56 32 L35.5 35.5 L32 32 Z" fill="currentColor" />
                      <path d="M56 32 L35.5 28.5 L32 32 Z" fill="none" />
                      <path d="M32 56 L28.5 35.5 L32 32 Z" fill="currentColor" />
                      <path d="M32 56 L35.5 35.5 L32 32 Z" fill="none" />
                      <path d="M8 32 L28.5 28.5 L32 32 Z" fill="currentColor" />
                      <path d="M8 32 L28.5 35.5 L32 32 Z" fill="none" />
                  </g>
                  <circle cx="32" cy="32" r="1.8" fill="var(--paper)" stroke="currentColor" strokeWidth="1" />
              </svg>

              {/* Wordmark */}
              <p className="footer__brand"><a href="#" aria-label="MCP-Audit home">mcp-audit</a></p>
              
              {/* Tagline */}
              <p className="footer__tagline">The secure route to AI agent deployment. Scan, proxy, and protect your infrastructure.</p>
              
              {/* Nav */}
              <nav className="footer__nav" aria-label="Footer">
                  <ul>
                      <li><a href="#">Platform</a></li>
                      <li><a href="#">Static Scan</a></li>
                      <li><a href="#">Runtime Gateway</a></li>
                      <li><a href="#">Telemetry</a></li>
                      <li><a href="#">Dashboard</a></li>
                      <li><a href="#">Docs</a></li>
                      <li><a href="#">GitHub</a></li>
                      <li><a href="#">Contact</a></li>
                  </ul>
              </nav>
              
              {/* Copyright */}
              <p className="footer__copy">© <span id="year">{new Date().getFullYear()}</span> MCP-Audit Architecture Team.</p>
          </div>

          {/* Video */}
          <video className="footer__video" autoPlay muted loop playsInline preload="auto" aria-hidden="true" tabIndex={-1} disablePictureInPicture>
              <source src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260928_144832_2b6b23aa-4416-4fcb-9df4-132349c59edc.mp4" type="video/mp4" />
          </video>
      </footer>
    </div>
  )
}

export default App
