# Roadmap

Phase 1 (MVP)
- [ ] Ingest CSV streams (Windows, Linux, SAP SAL)
- [ ] YAML rules (threshold + match)
- [ ] Alerts CSV + summary.txt
- [ ] CI with pytest

Phase 2
- [ ] Add MITRE ATT&CK and NIST/CIS mappings to alerts
- [ ] Publish Power BI template wired to alerts.csv
- [ ] Add threat hunting notebook (Jupyter) for pivoting on users/IPs/tcodes

Phase 3
- [ ] Add network logs (e.g., Zeek DNS/HTTP) and detections
- [ ] Container option (OpenSearch stack) with rule exporters
- [ ] Web UI (FastAPI/Streamlit) for upload and review