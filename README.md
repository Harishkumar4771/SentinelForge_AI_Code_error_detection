# 🛡️ SentinelForge

### Autonomous AI Security Engineering Team

**Detect. Test. Fix. Verify.**

SentinelForge is a full-stack AI-powered application security platform that acts like an autonomous security engineering team.

Instead of simply scanning code and reporting vulnerabilities, SentinelForge uses multiple specialized AI agents to **analyze source code, hunt vulnerabilities and bugs, generate security tests, propose fixes, and verify those fixes inside an isolated sandbox.**

> **Find → Test → Explain → Fix → Verify**

---

## 🚀 Why SentinelForge?

Modern software development increasingly relies on AI coding assistants and rapid development workflows. While this dramatically improves productivity, it can also introduce:

* Security vulnerabilities
* Logic bugs
* Insecure coding patterns
* Missing test coverage
* Hardcoded secrets
* Authentication and authorization flaws
* Unsafe input handling

Traditional tools usually operate independently:

```text
Static Analyzer → Findings
Test Framework  → Tests
Developer       → Fixes
CI/CD           → Verification
```

SentinelForge brings these stages together into one intelligent workflow:

```text
                    ┌──────────────────────┐
                    │   Source Repository  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Repository Analyzer  │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┼─────────────┐
                 ▼             ▼             ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
        │   Security   │ │   Testing    │ │ Bug Hunter   │
        │    Agent     │ │    Agent     │ │    Agent     │
        └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
               │                │                │
               └────────────────┼────────────────┘
                                ▼
                     ┌─────────────────────┐
                     │ Finding Correlator  │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │     Fix Agent       │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Docker Sandbox      │
                     └──────────┬──────────┘
                                │
                       ┌────────┴────────┐
                       ▼                 ▼
                Tests Execute      Security Rescan
                       │                 │
                       └────────┬────────┘
                                ▼
                     ┌─────────────────────┐
                     │  VERIFIED / FAILED  │
                     └─────────────────────┘
```

---

# ✨ Key Features

## 🤖 Multi-Agent Security Analysis

SentinelForge uses specialized agents rather than relying on a single AI prompt.

### 🔐 Security Auditor Agent

Identifies security vulnerabilities using a combination of AI reasoning and deterministic security tools.

Detects issues such as:

* SQL Injection
* Command Injection
* Cross-Site Scripting
* Path Traversal
* Hardcoded Secrets
* Weak Authentication
* Broken Authorization
* Insecure Cryptography
* Unsafe Deserialization
* SSRF
* Insecure Input Handling

---

### 🧪 Testing Agent

Automatically understands the application and generates tests designed to expose weaknesses.

It can generate:

* Unit tests
* API tests
* Security tests
* Boundary tests
* Negative tests
* Regression tests
* Edge-case tests

Example:

```text
Finding:
SQL Injection in /login

        ↓

Testing Agent

        ↓

Generated Test:
test_login_sql_injection()

        ↓

Execute Test

        ↓

Vulnerability Reproduced
```

---

### 🐛 Bug Hunter Agent

Security vulnerabilities aren't the only problem.

The Bug Hunter focuses on functional and business-logic bugs such as:

* Incorrect conditions
* Invalid state transitions
* Null handling
* Negative values
* Incorrect calculations
* Broken workflows
* Unexpected input combinations
* Missing validation

This allows SentinelForge to analyze both:

**Security + Software Quality**

---

### 🧠 Finding Correlator

Different agents may discover the same issue.

The Finding Correlator:

* Deduplicates findings
* Combines evidence
* Calculates confidence
* Maps findings to CWE/OWASP categories
* Identifies which agents discovered the issue
* Produces a unified finding

Example:

```text
Security Agent
      │
      ├── SQL Injection
      │
Testing Agent
      │
      └── SQL Injection reproduced
              │
              ▼
       Finding Correlator
              │
              ▼
        Unified Finding
```

---

### 🔧 Fix Agent

Once a vulnerability is confirmed, SentinelForge can generate a minimal code patch.

The Fix Agent:

1. Understands the vulnerability
2. Locates the vulnerable code
3. Generates a remediation
4. Produces a unified diff
5. Applies the patch only inside the sandbox

Example:

```diff
- query = "SELECT * FROM users WHERE id=" + user_id
+ query = "SELECT * FROM users WHERE id=?"
```

SentinelForge does **not** blindly modify the user's original repository.

---

# 🧪 Closed-Loop Verification

This is the core principle of SentinelForge.

> **An AI-generated fix is not considered successful simply because the AI says it is fixed.**

Every generated patch goes through an isolated verification workflow.

```text
Vulnerability Detected
        ↓
Security Test Generated
        ↓
Vulnerability Reproduced
        ↓
Patch Generated
        ↓
Patch Applied in Sandbox
        ↓
Existing Tests
        ↓
Generated Tests
        ↓
Security Rescan
        ↓
 ┌───────────────┐
 │               │
 ▼               ▼
VERIFIED       FAILED
```

Possible outcomes:

* ✅ VERIFIED
* ❌ FAILED
* ⚠️ PARTIALLY VERIFIED
* 👤 REQUIRES HUMAN REVIEW

---

# 🏗️ Architecture

```text
                         ┌──────────────────────┐
                         │      Next.js UI      │
                         │ React + TypeScript   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │      FastAPI         │
                         │      Backend         │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │  AI Orchestrator     │
                         │  LangGraph / Python  │
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
       Security Agent        Testing Agent         Bug Hunter
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │ Finding Correlator   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │      Fix Agent       │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Docker Sandbox     │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
              Test Execution                  Security Scan
                    │                               │
                    └───────────────┬───────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │ Verification Engine  │
                         └──────────────────────┘
```

---

# 🛠️ Technology Stack

## Frontend

* Next.js
* React
* TypeScript
* Tailwind CSS
* Lucide Icons
* Recharts

## Backend

* Python
* FastAPI
* Pydantic
* SQLAlchemy

## AI / Agent Layer

* IBM watsonx.ai / Granite
* LangGraph
* LLM-based agents
* Structured AI outputs

## Security Analysis

* Semgrep
* Bandit
* Gitleaks
* pip-audit
* Python AST

## Testing

* pytest
* pytest-cov
* Generated security tests
* Generated regression tests

## Infrastructure

* Docker
* PostgreSQL
* Git / GitHub
* Docker Compose

---

# 📁 Project Structure

```text
sentinelforge/
│
├── frontend/
│   ├── app/
│   ├── components/
│   ├── hooks/
│   ├── lib/
│   ├── types/
│   └── public/
│
├── backend/
│   ├── app/
│   │   ├── agents/
│   │   │   ├── security_agent.py
│   │   │   ├── testing_agent.py
│   │   │   ├── bug_hunter.py
│   │   │   └── fix_agent.py
│   │   │
│   │   ├── analyzers/
│   │   │   ├── semgrep.py
│   │   │   ├── bandit.py
│   │   │   ├── gitleaks.py
│   │   │   └── ast_analyzer.py
│   │   │
│   │   ├── correlation/
│   │   ├── sandbox/
│   │   ├── reports/
│   │   ├── services/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── api/
│   │   └── main.py
│   │
│   └── tests/
│
├── security-rules/
│
├── test-projects/
│   └── vulnerable-python-app/
│
├── docker/
│
├── docs/
│
├── docker-compose.yml
├── .env.example
├── README.md
└── LICENSE
```

---

# 🔄 Application Workflow

## 1. Upload Repository

The developer uploads a ZIP file or connects a Git repository.

```text
Upload Repository
       ↓
Repository Validation
       ↓
Language Detection
       ↓
Project Indexing
```

---

## 2. Repository Understanding

SentinelForge analyzes:

* File structure
* Dependencies
* Functions
* Classes
* API endpoints
* Database interactions
* Input/output flows
* Authentication mechanisms

---

## 3. Parallel Agent Analysis

The agents work independently.

```text
              Repository
                   │
       ┌───────────┼───────────┐
       ▼           ▼           ▼
   Security     Testing    Bug Hunter
     Agent       Agent       Agent
       │           │           │
       └───────────┼───────────┘
                   ▼
             Correlator
```

---

## 4. Findings Dashboard

Developers receive a unified security and quality report.

Each finding contains:

* Title
* Severity
* Confidence
* File
* Line number
* Code snippet
* CWE
* OWASP category
* Evidence
* Impact
* Recommendation
* Detection source
* Verification status

---

## 5. Generate Fix

The developer can request a fix for a finding.

SentinelForge generates a minimal patch.

```text
Finding
   ↓
AI Reasoning
   ↓
Patch Generation
   ↓
Unified Diff
```

---

## 6. Sandbox Verification

The patch is applied inside an isolated Docker environment.

The system then executes:

```text
Existing Tests
      +
Generated Tests
      +
Security Scan
      +
Regression Checks
```

---

## 7. Final Verification

If all relevant checks pass:

```text
╔════════════════════════════╗
║      ✓ FIX VERIFIED        ║
║                            ║
║ Vulnerability resolved     ║
║ Regression tests passed    ║
║ Security rescan passed     ║
╚════════════════════════════╝
```

Otherwise:

```text
╔════════════════════════════╗
║      ✗ VERIFICATION FAILED ║
║                            ║
║ Patch requires revision    ║
╚════════════════════════════╝
```

---

# 📊 Dashboard

The main dashboard provides a security engineering overview.

### Example metrics

```text
┌────────────────────────────────────────────┐
│              SENTINELFORGE                 │
├──────────────┬──────────────┬──────────────┤
│ Security     │ Critical     │ High         │
│ Score: 82    │     1        │      3       │
├──────────────┼──────────────┼──────────────┤
│ Medium       │ Bugs         │ Tests        │
│     5        │     4        │ 28 Generated │
└──────────────┴──────────────┴──────────────┘
```

Additional views:

* Security Findings
* Agent Activity
* Generated Tests
* Patch History
* Verification Results
* Security Trends
* Reports

---

# 🤖 Agent Activity

The interface provides visibility into what the agents are doing.

Example:

```text
✓ Repository Analyzer       Completed
✓ Security Auditor           12 findings
✓ Testing Agent              18 tests generated
✓ Bug Hunter                 4 bugs found
✓ Finding Correlator         2 duplicates removed
✓ Fix Agent                  3 patches generated
✓ Sandbox                    Verification running
✓ Security Rescan            Completed
```

This makes the multi-agent architecture visible during the demo.

---

# 📋 Example Finding

```json
{
  "title": "SQL Injection",
  "severity": "CRITICAL",
  "confidence": 0.96,
  "category": "Injection",
  "cwe": "CWE-89",
  "owasp": "A03:2021-Injection",
  "file_path": "app/database.py",
  "line_number": 42,
  "evidence": [
    "Semgrep detected unsafe SQL construction",
    "AST analysis confirmed user-controlled data flow"
  ],
  "impact": "An attacker may manipulate database queries.",
  "recommendation": "Use parameterized queries.",
  "detected_by": [
    "security_agent",
    "testing_agent"
  ],
  "verified": false
}
```

---

# 🧪 Demo Application

SentinelForge includes a deliberately vulnerable Python/Flask application for demonstration.

The demo application contains controlled examples of:

* SQL Injection
* Hardcoded secrets
* Weak authentication
* Path traversal
* Missing authorization
* Input validation issues
* Business-logic bugs

The demo allows judges to observe the complete lifecycle:

```text
Vulnerable Application
          ↓
      Scan Code
          ↓
   Detect Vulnerability
          ↓
     Generate Test
          ↓
   Reproduce Issue
          ↓
    Generate Patch
          ↓
 Apply Patch in Docker
          ↓
   Run Regression Tests
          ↓
     Security Rescan
          ↓
      FIX VERIFIED
```

---

# 🔌 API

Example API endpoints:

| Method | Endpoint                   | Purpose             |
| ------ | -------------------------- | ------------------- |
| POST   | `/api/projects`            | Create project      |
| GET    | `/api/projects`            | List projects       |
| POST   | `/api/projects/{id}/scan`  | Start scan          |
| GET    | `/api/scans/{id}`          | Scan status         |
| GET    | `/api/scans/{id}/findings` | Get findings        |
| GET    | `/api/scans/{id}/tests`    | Get generated tests |
| GET    | `/api/scans/{id}/agents`   | Agent activity      |
| POST   | `/api/findings/{id}/fix`   | Generate fix        |
| POST   | `/api/patches/{id}/verify` | Verify patch        |
| GET    | `/api/scans/{id}/report`   | Generate report     |

---

# 🔐 Security Design

SentinelForge is itself a security-sensitive application.

Therefore, uploaded repositories must **never be blindly executed on the host system**.

Security controls include:

* Docker isolation
* Resource limits
* Execution timeouts
* Restricted network access
* Safe file handling
* Path traversal protection
* No host-level execution of uploaded code
* No secrets exposed to scanned applications
* Structured validation of AI outputs
* Generated patches isolated from original repositories
* Human approval before deployment

### Important principle

> **AI proposes. Deterministic tools verify. Humans remain in control.**

---

# 🧠 AI Architecture

SentinelForge uses AI for tasks that require reasoning and deterministic tools for tasks that require objective verification.

### AI is responsible for:

* Code understanding
* Vulnerability reasoning
* Bug reasoning
* Test generation
* Patch generation
* Explanation
* Remediation suggestions

### Deterministic tools are responsible for:

* Static analysis
* Secret scanning
* Dependency scanning
* Test execution
* Code coverage
* Security rescanning
* Patch verification

This hybrid architecture reduces dependence on LLM claims alone.

---

# 🏆 What Makes SentinelForge Different?

Traditional security scanners generally follow:

```text
Scan → Report
```

SentinelForge aims for:

```text
Detect
   ↓
Understand
   ↓
Test
   ↓
Reproduce
   ↓
Fix
   ↓
Verify
   ↓
Report
```

The important distinction is the **closed feedback loop**.

A vulnerability isn't simply marked fixed because an AI generated a patch.

The system attempts to prove the fix using:

* Tests
* Regression checks
* Security scanners
* Sandbox execution
* Rescanning

---

# 🎯 Target Users

SentinelForge is designed for:

### 👨‍💻 Developers

Find and understand vulnerabilities while building applications.

### 🔐 Security Engineers

Automate repetitive vulnerability analysis and verification.

### 🏢 Development Teams

Integrate security and testing into the development workflow.

### 🚀 Startups

Improve application security without requiring a large dedicated security team.

### 🧑‍💼 Engineering Leads

Receive security and software-quality reports with actionable remediation.

---

# 🚀 Getting Started

## Prerequisites

Install:

* Python 3.11+
* Node.js 20+
* Docker
* PostgreSQL
* Git

Optional:

* IBM watsonx.ai credentials
* GitHub token

---

## Clone Repository

```bash
git clone https://github.com/<your-username>/sentinelforge.git

cd sentinelforge
```

---

## Start Infrastructure

```bash
docker compose up -d
```

---

## Backend

```bash
cd backend

python -m venv .venv
```

### Linux/macOS

```bash
source .venv/bin/activate
```

### Windows

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start FastAPI:

```bash
uvicorn app.main:app --reload
```

Backend will be available at:

```text
http://localhost:8000
```

API documentation:

```text
http://localhost:8000/docs
```

---

## Frontend

```bash
cd frontend

npm install

npm run dev
```

Frontend will be available at:

```text
http://localhost:3000
```

---

# ⚙️ Environment Variables

Create:

```text
.env
```

Example:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/sentinelforge

AI_PROVIDER=mock

WATSONX_API_KEY=
WATSONX_PROJECT_ID=
WATSONX_URL=

GITHUB_TOKEN=
```

For local development, the project should support a **Mock AI Provider** so the application can run without external API credentials.

---

# 🧪 Running Tests

Backend tests:

```bash
pytest
```

With coverage:

```bash
pytest --cov=app
```

Frontend:

```bash
npm test
```

---

# 🗺️ Roadmap

## Phase 1 — Foundation

* [x] Project architecture
* [ ] Frontend dashboard
* [ ] FastAPI backend
* [ ] PostgreSQL integration
* [ ] Docker environment

## Phase 2 — Security Analysis

* [ ] Semgrep integration
* [ ] Bandit integration
* [ ] Gitleaks integration
* [ ] Dependency scanning
* [ ] Security Auditor Agent

## Phase 3 — AI Testing

* [ ] Testing Agent
* [ ] Automated pytest generation
* [ ] Security test generation
* [ ] Bug Hunter Agent

## Phase 4 — Autonomous Remediation

* [ ] Finding Correlator
* [ ] Fix Agent
* [ ] Patch generation
* [ ] Unified diff viewer

## Phase 5 — Verification

* [ ] Docker sandbox
* [ ] Automated test execution
* [ ] Security rescan
* [ ] Patch verification
* [ ] Verification audit trail

## Phase 6 — Hackathon Polish

* [ ] Agent activity visualization
* [ ] Security score
* [ ] Reports
* [ ] Demo project
* [ ] UI/UX refinement
* [ ] Deployment

---

# 🏁 Hackathon Demo

The recommended live demo follows one vulnerable application through the complete SentinelForge pipeline.

### Step 1

Upload vulnerable Flask application.

### Step 2

Start autonomous scan.

### Step 3

Security Agent discovers SQL Injection.

### Step 4

Testing Agent generates a test.

### Step 5

Test successfully reproduces the vulnerability.

### Step 6

Bug Hunter discovers a separate business-logic bug.

### Step 7

Fix Agent generates a patch.

### Step 8

Patch is applied inside Docker.

### Step 9

Tests and security scans execute.

### Step 10

The vulnerability disappears during the security rescan.

### Step 11

Dashboard displays:

```text
✓ Vulnerability Detected
✓ Exploit/Test Reproduced
✓ Patch Generated
✓ Patch Applied
✓ Regression Tests Passed
✓ Security Rescan Passed

          FIX VERIFIED
```

---

# 🧩 IBM Integration

SentinelForge can use **IBM watsonx.ai / Granite** as the reasoning layer for:

* Source-code analysis
* Vulnerability explanations
* Test generation
* Bug reasoning
* Patch generation
* Finding correlation
* Remediation recommendations

IBM Bob can assist throughout the software-development lifecycle, including:

* Project scaffolding
* Code generation
* Refactoring
* Debugging
* Test creation
* Documentation
* Architecture implementation

> IBM-specific capabilities should only be enabled or claimed in the final implementation when they are actually integrated into the project.

---

# 📄 License

This project is developed for educational, research, and hackathon purposes.

Add your chosen license here, for example:

```text
MIT License
```

---

# 👥 Team

**SentinelForge**

> Building an autonomous AI security engineering workflow for the next generation of software development.

---

## ⭐ Core Vision

SentinelForge isn't designed to be another vulnerability scanner.

It is designed to behave like an **AI security engineering team**:

```text
        ┌────────────────────────────┐
        │       SENTINELFORGE        │
        ├────────────────────────────┤
        │                            │
        │  🔐 Security Auditor       │
        │  🧪 Testing Agent          │
        │  🐛 Bug Hunter             │
        │  🧠 Finding Correlator     │
        │  🔧 Fix Agent              │
        │  📦 Sandbox                │
        │  ✓ Verification Engine     │
        │                            │
        └────────────────────────────┘

             DETECT
                ↓
              TEST
                ↓
             EXPLAIN
                ↓
               FIX
                ↓
             VERIFY
```

**SentinelForge — Detect. Test. Fix. Verify.**
