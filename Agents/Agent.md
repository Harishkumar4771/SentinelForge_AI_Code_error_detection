MASTER BUILD PROMPT — SENTINELFORGE
You are the lead software architect and senior full-stack AI/security engineer responsible for building a production-quality hackathon MVP called SentinelForge.
1. PRODUCT
Name
SentinelForge
Tagline
AI Security Engineering Team — Detect. Test. Fix. Verify.
Product Definition
SentinelForge is a multi-agent AI-powered application security platform that analyzes software repositories, detects security vulnerabilities and bugs, automatically generates tests, proposes code fixes, and verifies those fixes inside an isolated sandbox.
The product must NOT behave like a simple chatbot or code-review assistant.
Its core workflow is:
Repository
    ↓
Repository Understanding
    ↓
AI Orchestrator
    ↓
┌────────────────┬────────────────┬─────────────────┐
│ Security Agent │ Testing Agent  │ Bug Hunter Agent│
└────────────────┴────────────────┴─────────────────┘
                    ↓
            Finding Correlator
                    ↓
               Fix Agent
                    ↓
             Docker Sandbox
                    ↓
        Tests + Security Rescan
                    ↓
          ┌─────────┴─────────┐
          ↓                   ↓
       VERIFIED             FAILED
          ↓                   ↓
       Report          Repair / Retry

The most important product principle is:
Never claim that an AI-generated fix is correct merely because the LLM says so. The system must attempt to verify the fix using deterministic tools and tests.

2. PRIMARY GOAL
Build a working MVP that allows a user to:
Upload a software repository as a ZIP file.
Analyze the repository.
Detect vulnerabilities.
Detect functional/logic bugs.
Generate automated tests.
Execute tests safely.
Correlate findings from multiple agents.
Generate remediation patches.
Apply patches inside an isolated Docker environment.
Re-run tests and security scans.
Determine whether the fix is verified.
Display everything in a professional security dashboard.
Generate a final security report.
The application should feel like an autonomous AI security engineering team.

3. IMPORTANT SCOPE RULE
Do NOT attempt to support every programming language initially.
MVP language
Support Python first.
Design the architecture so additional languages can be added later.
Prioritize a fully working Python workflow over partially implemented multi-language support.

4. TECHNOLOGY STACK
Use:
Frontend
Next.js
React
TypeScript
Tailwind CSS
Lucide icons
Recharts if charts are needed
Backend
Python
FastAPI
Pydantic
SQLAlchemy
Database
PostgreSQL
For local development, provide Docker Compose.
AI / Agent Layer
Create a provider abstraction.
The architecture must support:
AIProvider
├── IBMWatsonxProvider
└── MockProvider

The production provider should be designed for IBM watsonx.ai / Granite.
Do NOT hardcode the application to a single model.
Use environment variables for model configuration.
Agent orchestration
Use LangGraph if practical.
If LangGraph creates unnecessary complexity for the MVP, implement a clean Python orchestration layer with interfaces that can later be migrated to LangGraph.
Security tools
Integrate where practical:
Semgrep
Bandit
Gitleaks
pip-audit
Python AST
Testing
pytest
coverage
Sandbox
Docker

5. SYSTEM ARCHITECTURE
Use this logical architecture:
                   ┌──────────────────┐
                    │      USER        │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  NEXT.JS CLIENT  │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    FASTAPI       │
                    │    API SERVER    │
                    └────────┬─────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │   ORCHESTRATOR       │
                  │                      │
                  │ Task decomposition   │
                  │ Agent coordination   │
                  │ Workflow management  │
                  └──────────┬───────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
   │ SECURITY     │  │ TESTING      │  │ BUG HUNTER   │
   │ AGENT        │  │ AGENT        │  │ AGENT        │
   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
          │                 │                 │
          └─────────────────┼─────────────────┘
                            ▼
                 ┌────────────────────┐
                 │ FINDING CORRELATOR │
                 └──────────┬─────────┘
                            ▼
                    ┌──────────────┐
                    │  FIX AGENT   │
                    └──────┬───────┘
                           ▼
                  ┌──────────────────┐
                  │  DOCKER SANDBOX  │
                  └────────┬─────────┘
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
            TESTS PASS           TESTS FAIL
                 │                   │
                 ▼                   ▼
          SECURITY RESCAN        REPAIR LOOP
                 │
                 ▼
          ┌───────────────┐
          │ FINAL REPORT  │
          └───────────────┘


6. REPOSITORY STRUCTURE
Create a clean monorepo:
sentinelforge/
│
├── frontend/
│   ├── app/
│   ├── components/
│   ├── lib/
│   ├── hooks/
│   ├── types/
│   └── public/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── agents/
│   │   ├── analyzers/
│   │   ├── correlation/
│   │   ├── sandbox/
│   │   ├── reports/
│   │   ├── services/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── core/
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


7. CORE DATA MODEL
Create database models for:
Project
id
name
description
created_at
status

Scan
id
project_id
status
started_at
completed_at
security_score
critical_count
high_count
medium_count
low_count

Finding
id
scan_id
title
description
severity
confidence
category
cwe
owasp
file_path
line_number
code_snippet
evidence
impact
recommendation
status
detected_by
verified

TestCase
id
scan_id
name
description
test_code
type
status
output

Patch
id
finding_id
original_code
patched_code
diff
validation_status
validation_output

AgentExecution
id
scan_id
agent_name
status
started_at
completed_at
message


8. STANDARD FINDING FORMAT
Every agent MUST return findings using the same schema.
Example:
{
  "title": "SQL Injection",
  "description": "User-controlled input is directly concatenated into a SQL query.",
  "severity": "CRITICAL",
  "confidence": 0.96,
  "category": "Injection",
  "cwe": "CWE-89",
  "owasp": "A03:2021-Injection",
  "file_path": "app/database.py",
  "line_number": 42,
  "code_snippet": "query = 'SELECT ...' + user_id",
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

Use Pydantic models to enforce this schema.

9. SECURITY AUDITOR AGENT
The Security Auditor Agent should combine deterministic tools and AI reasoning.
Pipeline:
Repository
 ↓
File discovery
 ↓
AST analysis
 ↓
Semgrep
 ↓
Bandit
 ↓
Gitleaks
 ↓
pip-audit
 ↓
AI analysis
 ↓
Normalized findings

Initially detect at least:
SQL injection
Command injection
XSS
Path traversal
Hardcoded secrets
Weak password handling
Insecure cryptography
Insecure deserialization
Broken authorization patterns
SSRF
Do not claim that detection is perfect.
Every finding should include evidence and confidence.

10. TESTING AGENT
The Testing Agent must inspect the application and generate tests.
It should identify:
functions
classes
API endpoints
inputs
outputs
branches
edge cases
Generate:
Unit tests
def test_function():
    ...

Boundary tests
0
-1
MAX_INT
empty string
None
very large input

Security tests
SQL injection payloads
path traversal payloads
malformed input
authorization violations

API tests
For detected HTTP endpoints.
The agent should save generated tests and execute them using pytest.

11. BUG HUNTER AGENT
The Bug Hunter Agent must focus on functional and logical defects.
Examples:
incorrect conditions
unreachable branches
incorrect calculations
negative values
null handling
state transition errors
authorization logic
business logic flaws
inconsistent error handling
Do not duplicate every finding from the Security Agent.
Its goal is:
Find bugs that may make the software behave incorrectly even when no conventional security vulnerability exists.

12. FINDING CORRELATOR
The Finding Correlator receives findings from all agents.
It should:
Deduplicate findings.
Detect related findings.
Merge evidence.
Calculate confidence.
Determine severity.
Identify which agents independently detected the issue.
Example:
Security Agent:
SQL Injection

Testing Agent:
Malicious payload causes database error

Bug Hunter:
User input reaches raw SQL

          ↓

Unified Finding

SQL Injection
Severity: CRITICAL
Confidence: 96%

Evidence:
✓ Static analysis
✓ Dynamic test
✓ Data flow analysis


13. FIX AGENT
The Fix Agent receives a validated finding.
It should:
Read the relevant source code.
Understand surrounding context.
Generate a minimal patch.
Produce a unified diff.
Explain the remediation.
Return the patch for validation.
Example:
- query = "SELECT * FROM users WHERE id=" + user_id
+ query = "SELECT * FROM users WHERE id = ?"
+ cursor.execute(query, (user_id,))

Never modify the user's original repository directly.
All patches must initially be applied only inside a sandbox.

14. SANDBOX VERIFICATION
This is a core feature.
Create a Docker-based isolated execution environment.
Workflow:
Original repository
       ↓
Create temporary workspace
       ↓
Apply generated patch
       ↓
Install dependencies safely
       ↓
Run existing tests
       ↓
Run generated tests
       ↓
Run security scanners
       ↓
Collect results
       ↓
Determine verification status

Possible states:
VERIFIED
FAILED
PARTIALLY_VERIFIED
REQUIRES_HUMAN_REVIEW

A patch can only be marked:
VERIFIED

if relevant tests pass and the targeted security finding is no longer detected.

15. ORCHESTRATOR
Implement the complete workflow:
START
 ↓
Create scan
 ↓
Analyze repository
 ↓
Run Security Agent
 ↓
Run Testing Agent
 ↓
Run Bug Hunter
 ↓
Correlate findings
 ↓
Generate fixes for high-confidence findings
 ↓
Validate patches
 ↓
Rescan
 ↓
Generate final report
 ↓
COMPLETE

The orchestrator should expose agent execution status to the frontend.

16. FRONTEND
Create a polished cybersecurity dashboard.
Design language:
dark security/SOC aesthetic
professional
minimal
high information density
subtle animations
responsive
no excessive gradients
no childish graphics
Main navigation:
Dashboard
Projects
Scans
Findings
Tests
Fixes
Agent Activity
Reports


17. DASHBOARD
Show:
Security Score
Critical Vulnerabilities
High Vulnerabilities
Medium Vulnerabilities
Low Vulnerabilities
Bugs Detected
Tests Generated
Tests Passed
Verified Fixes

Include charts:
vulnerability severity distribution
findings by category
agent activity
test results

18. SCAN PAGE
Show real-time scan progress.
Example:
SentinelForge Security Scan

✓ Repository analyzed
✓ Security Auditor completed
● Testing Agent running
○ Bug Hunter
○ Finding Correlation
○ Fix Verification

Agent Activity

Security Auditor     ███████████████ 100%
Testing Agent        ██████████░░░░░  68%
Bug Hunter           ███░░░░░░░░░░░  25%

Use WebSockets or Server-Sent Events if practical.
If real-time infrastructure adds excessive complexity, implement polling.

19. FINDINGS PAGE
Each finding should show:
CRITICAL
SQL Injection

CWE-89
OWASP A03:2021

File:
app/database.py

Line:
42

Confidence:
96%

Detected by:
Security Agent
Testing Agent

Evidence:
...

Impact:
...

Recommendation:
...

[View Code]
[Generate Fix]


20. FIX VERIFICATION PAGE
Create a visually impressive workflow:
Vulnerability Detected
        ↓
Exploit/Test Generated
        ↓
Issue Reproduced
        ↓
Patch Generated
        ↓
Patch Applied in Sandbox
        ↓
Regression Tests
        ✓
Security Rescan
        ✓
        ↓
FIX VERIFIED

This should be one of the most visually prominent parts of the application.

21. AGENT ACTIVITY PAGE
Show each agent as an independent worker.
Example:
SECURITY AUDITOR
Status: Completed
Findings: 7

TESTING AGENT
Status: Running
Tests generated: 32
Passed: 25
Failed: 7

BUG HUNTER
Status: Completed
Logic issues: 3

FIX AGENT
Status: 2 patches verified

Also display an event timeline.

22. REPORT GENERATION
Generate a professional security report.
Include:
Executive Summary

Security Score

Vulnerability Summary

Critical Findings

High Findings

Functional Bugs

Generated Tests

Remediation Summary

Verified Fixes

Remaining Risks

Recommendations

Allow download as PDF if practical.

23. DEMO APPLICATION
Create a deliberately vulnerable Python Flask application under:
test-projects/vulnerable-python-app/

It should contain controlled examples of:
SQL injection
hardcoded secret
weak authentication
path traversal
missing authorization
business logic bug
insufficient input validation
This application will be used for the hackathon demo.
DO NOT create dangerous real-world malware or destructive functionality.
The vulnerabilities must be intentionally isolated and used only as a local demonstration target.

24. AI PROMPT DESIGN
Do not send entire repositories blindly to the LLM.
First create a structured code context:
Project metadata
Language
Files
Relevant functions
AST information
Security tool findings
Relevant code snippets
Dependencies
Existing tests

Use targeted context windows.
The AI should always be instructed:
You are analyzing source code for defensive software security.

Do not invent evidence.

Only report vulnerabilities when there is reasonable evidence.

Clearly distinguish:
- confirmed
- probable
- potential

Return structured JSON matching the Finding schema.


25. SECURITY PRINCIPLES
Implement:
never execute uploaded code directly on the host
use isolated containers
impose execution timeouts
restrict network access where possible
limit CPU/memory
sanitize file paths
never expose environment secrets to scanned code
never execute generated patches outside the sandbox
validate AI-generated structured output
never automatically deploy a generated patch
The platform itself must be secure.

26. API ENDPOINTS
Implement approximately:
POST   /api/projects
GET    /api/projects

POST   /api/projects/{id}/scan
GET    /api/scans/{id}

GET    /api/scans/{id}/findings
GET    /api/scans/{id}/tests
GET    /api/scans/{id}/agents

POST   /api/findings/{id}/fix
POST   /api/patches/{id}/verify

GET    /api/scans/{id}/report

Use OpenAPI documentation automatically through FastAPI.

27. ERROR HANDLING
The system must gracefully handle:
invalid ZIP
unsupported repository
missing dependencies
scanner failure
LLM timeout
malformed LLM response
Docker failure
test timeout
patch failure
database failure
Never allow one failed agent to crash the entire scan.

28. CONFIGURATION
Create .env.example:
DATABASE_URL=
IBM_WATSONX_URL=
IBM_WATSONX_API_KEY=
IBM_WATSONX_PROJECT_ID=
IBM_MODEL_ID=
DOCKER_HOST=

Never hardcode credentials.

29. TESTING THE PLATFORM
Create automated tests for:
Backend
API tests
database tests
agent tests
finding schema validation
correlation tests
sandbox tests
Frontend
component tests
API integration tests
End-to-end
Test:
Upload vulnerable project
 ↓
Run scan
 ↓
Detect vulnerability
 ↓
Generate test
 ↓
Generate patch
 ↓
Verify patch
 ↓
Generate report


30. DEMO SUCCESS CRITERIA
The MVP is considered successful when we can demonstrate this complete flow live:
1. Upload vulnerable Flask application.

2. SentinelForge discovers the project.

3. Security Agent identifies SQL injection.

4. Testing Agent generates an exploit/security test.

5. Test reproduces the vulnerability.

6. Bug Hunter identifies a separate business logic flaw.

7. Finding Correlator combines evidence.

8. Fix Agent generates a patch.

9. Patch is applied inside Docker.

10. Original tests run.

11. Generated security test runs.

12. Security scanner runs again.

13. Vulnerability is shown as VERIFIED FIXED.

14. Dashboard displays the complete audit trail.

15. Final security report is generated.

This is the primary demo.

31. DEVELOPMENT STRATEGY
Do NOT attempt to build everything simultaneously.
Build vertically.
Milestone 1
Repository upload → scan → findings dashboard.
Milestone 2
Security Agent → real security tools.
Milestone 3
Testing Agent → generated pytest tests.
Milestone 4
Bug Hunter.
Milestone 5
Finding Correlator.
Milestone 6
Fix Agent.
Milestone 7
Docker verification.
Milestone 8
Polish dashboard + report.
At the end of each milestone, make sure the application still runs.

32. IMPORTANT IMPLEMENTATION RULES
Prefer working functionality over placeholder UI.
Do not create fake scan results.
Do not hardcode vulnerability findings.
Do not simulate "AI agents" with static text.
Use real security tools wherever practical.
Keep agents modular.
Use typed schemas.
Keep AI provider abstraction separate from business logic.
Keep security scanning separate from LLM reasoning.
Never trust an AI-generated patch without verification.
Keep the MVP focused on Python.
Write clean, documented code.
Add logging for every agent execution.
Make failures recoverable.
Never expose API keys in frontend code.

33. UI QUALITY BAR
The application should look like a real cybersecurity product that could be shown to enterprise users.
Avoid:
generic AI chatbot appearance
excessive rounded cards
meaningless animations
fake metrics
unnecessary gradients
giant "AI" labels everywhere
Prefer:
security dashboard aesthetic
severity indicators
code diff viewer
agent timeline
scan progress
evidence panels
vulnerability details
verification status
clear information hierarchy

34. FINAL OUTPUT REQUIRED FROM YOU
When implementation begins:
First
Inspect the environment and available tools.
Then
Create the project structure.
Then
Implement the MVP incrementally.
After each major component:
Run tests.
Fix errors.
Verify functionality.
Continue.
Do not simply generate a large amount of code without testing it.
At completion provide:
1. Architecture summary
2. Files created
3. How to run locally
4. Environment variables required
5. Docker instructions
6. Test results
7. Supported vulnerability types
8. Known limitations
9. Demo instructions
10. Future improvements

FINAL PRODUCT PRINCIPLE
Remember:
SentinelForge is not an AI that tells developers their code is insecure.
It is an AI security engineering team that:
UNDERSTANDS → HUNTS → TESTS → FIXES → VERIFIES
The final product should make this workflow obvious within the first 30 seconds of using the application.

