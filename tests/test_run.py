from pathlib import Path
import pandas as pd
from src.loaders import load_streams
from src.engine import load_rules, run_rules

def test_end_to_end(tmp_path: Path):
    events = load_streams(Path("data/streams"))
    rules = load_rules(Path("rules"))
    alerts = run_rules(events, rules)
    # Expect at least SAP burst, SAP privilege change, RFC anomaly, and Windows brute force
    ids = set(alerts["rule_id"].tolist())
    assert "SAP-FAIL-LOGON-BURST" in ids
    assert "SAP-PRIV-CHANGE" in ids
    assert "SAP-RFC-ANOM" in ids
    assert "WIN-REMOTE-BRUTE" in ids