# SAP-in-a-SOC Lab

A hands-on blue-team lab that simulates a small SOC focused on Security+/CySA+ skills with SAP signal included.

What it does (MVP)
- Ingests sample logs (Windows, Linux, SAP Security Audit Log)
- Runs YAML detection rules (brute force, privilege changes, RFC anomalies, sudo/admin actions)
- Outputs alerts to CSV + a brief summary for reporting

Why it helps (Security+/CySA+)
- Security+: account management, authentication monitoring, auditing and reporting
- CySA+: log analysis, detection engineering, incident triage, severity, and simple KPIs

Quick start
1) Requirements
   - Python 3.10+
   - pip install -r requirements.txt

2) Run detections
   - python -m src.cli run --streams data/streams --rules rules --out out

3) Outputs (in ./out)
   - alerts.csv — all generated alerts with rule metadata
   - summary.txt — counts by severity and rule

Repo structure
- src/ — loaders and a simple rules engine
- rules/ — YAML detections (Windows, Linux, SAP SAL)
- data/streams/ — simulated log sources (CSV)
- tests/ — lightweight tests to validate the lab
- .github/workflows/ — CI (pytest)

Example detections included
- SAP: multiple failed logons burst (15m, >=5), privilege/admin changes, RFC from unusual sources
- Windows: remote logon (type 10) brute force
- Linux: suspicious sudo/admin action

Notes
- All data is simulated. Do not include real organizational logs.
- Extend the lab with your own streams/rules and add dashboards (Power BI/Athena/Notebook) as next steps.

Roadmap (short)
- Map each alert to MITRE ATT&CK and NIST/CIS in output
- Add a Power BI template wired to alerts.csv
- Add Jupyter hunting notebooks