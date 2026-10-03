# MCP-Audit: The Enterprise Security Control Plane for AI Agents

[![PyPI version](https://badge.fury.io/py/mcp-audit.svg)](https://badge.fury.io/py/mcp-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**MCP-Audit** is the industry's first comprehensive security firewall and static analysis tool for the **Model Context Protocol (MCP)**. 

As AI agents gain autonomous access to local filesystems, production databases, and sensitive APIs via MCP, security becomes paramount. MCP-Audit provides a complete "Shift-Left to Runtime" pipeline that ensures AI agents only perform strictly authorized actions.

---

## 🚀 Features

MCP-Audit is built in three powerful phases, creating a true Enterprise Security Control Plane:

### 1. Static Analysis (SAST) CI/CD Engine
Catch vulnerabilities *before* they are deployed. The `mcp-audit scan` CLI parses `mcp.json` schemas in your repository to detect:
*   **Arbitrary Code Execution:** Detects dangerous tools like `bash_eval` or `python_exec`.
*   **Path Traversal & Schema Bombs:** Identifies unrestricted file system access (`read_file` without sandboxing).
*   **Prompt Injection Risks:** AI-assisted heuristics to flag tools vulnerable to malicious system prompts.

### 2. Runtime Security Gateway (DAST Proxy)
Don't trust the LLM. The **Security Gateway Proxy** sits invisibly between your AI Agent and your MCP Server. 
*   **Dynamic Payload Inspection:** Intercepts JSON-RPC traffic over stdio/HTTP.
*   **Command Injection Blocking:** Blocks malicious parameters injected by hallucinating or hijacked agents.
*   **Transparent Forwarding:** Natively forwards cleared requests to your downstream servers using our `ForwardingEngine`.

### 3. Enterprise Control Plane & React Dashboard
Security Operations Centers (SOC) cannot manage what they cannot see.
*   **Structured Telemetry:** Automatically formats all allowed/blocked requests into **OCSF (Open Cybersecurity Schema Framework)** JSON logs, ready for SIEM ingestion (Splunk, Datadog).
*   **FastAPI Backend & PostgreSQL:** Tracks multi-tenant risk metrics and historical vulnerability scores over time.
*   **Premium React Dashboard:** A highly-polished, enterprise-grade interface to visualize blocked request volumes and active risks in real-time.

---

## 🛠 Installation

```bash
# Install the CLI tool
pip install mcp-audit

# Or install from source
git clone https://github.com/shivasync0/MCP-Audit.git
cd MCP-Audit
pip install -e .
```

---

## 💻 Developer Integration

### 1. CI/CD Pipeline (GitHub Actions)
Prevent vulnerable MCP tools from being merged by adding our CLI to your pre-commit hooks or CI/CD pipelines.

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: pip install mcp-audit
      - run: mcp-audit scan ./mcp-servers/
```

### 2. Python Gateway Integration
Programmatically instantiate the Gateway Proxy to wrap your existing MCP Server deployments in Python.

```python
from mcp_audit.gateway import SecurityGatewayProxy
from mcp_audit.gateway.forwarder import ForwardingEngine

proxy = SecurityGatewayProxy()
forwarder = ForwardingEngine("npx @modelcontextprotocol/server-postgres")

# Intercept and forward RPC requests natively
async def handle_request(rpc_req):
    if proxy.evaluate_request(rpc_req):
        return await forwarder.forward_request(rpc_req)
```

---

## 🏗 Enterprise Deployment (Docker)

To run the full Control Plane (Postgres Database, FastAPI Backend, and React Dashboard), use Docker Compose:

```bash
# 1. Spin up the Control Plane Backend
docker-compose up --build -d

# 2. Start the React Frontend Dashboard
cd dashboard
npm install
npm run dev
```
Navigate to **http://localhost:5173** to view the live dashboard!

---

## 🎨 Architecture & Design
The React Dashboard and marketing site (`website.html`) are custom-styled using our unique **Meridian Vintage** design system (Pale Sage & Dark Green Ink) providing a premium, unified brand experience.

## 📄 License
This project is licensed under the MIT License.
