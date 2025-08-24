from pathlib import Path
from typing import List, Dict, Any
import pandas as pd
import yaml

def load_rules(rules_dir: Path) -> List[Dict[str, Any]]:
    rule_files = sorted(Path(rules_dir).glob("*.yaml"))
    rules = []
    for rf in rule_files:
        with open(rf, "r", encoding="utf-8") as f:
            r = yaml.safe_load(f)
            if isinstance(r, dict):
                r["__file__"] = rf.name
                rules.append(r)
    return rules

def _apply_op(series: pd.Series, op: str, value):
    op = (op or "").lower()
    if op == "equals":
        return series.astype(str) == str(value)
    if op == "in":
        values = [str(v) for v in value] if isinstance(value, (list, tuple, set)) else [str(value)]
        return series.astype(str).isin(values)
    if op == "contains":
        return series.astype(str).str.contains(str(value), na=False, case=False)
    if op == "startswith":
        return series.astype(str).str.startswith(str(value), na=False)
    if op == "not_startswith_any":
        prefixes = [str(v) for v in value] if isinstance(value, (list, tuple, set)) else [str(value)]
        s = series.astype(str).fillna("")
        mask = ~pd.concat([s.str.startswith(p, na=False) for p in prefixes], axis=1).any(axis=1)
        return mask
    # Default: no filter (all True)
    return pd.Series([True] * len(series), index=series.index)

def _filter_df(df: pd.DataFrame, conditions: List[Dict[str, Any]]) -> pd.DataFrame:
    if not conditions:
        return df
    mask = pd.Series([True] * len(df), index=df.index)
    for c in conditions:
        field = c.get("field")
        op = c.get("op", "equals")
        value = c.get("value")
        mask &= _apply_op(df.get(field, pd.Series([None]*len(df))), op, value)
    return df[mask]

def run_rules(events: pd.DataFrame, rules: List[Dict[str, Any]]) -> pd.DataFrame:
    alerts = []
    if events.empty:
        return pd.DataFrame(columns=[
            "rule_id", "title", "severity", "timestamp_start", "timestamp_end", "user", "source_ip", "count", "sample_events"
        ])

    for r in rules:
        rtype = (r.get("type") or "match").lower()
        rid = r.get("id") or r.get("title") or r.get("__file__")
        title = r.get("title") or rid
        severity = r.get("severity", "medium")

        if rtype == "match":
            where = r.get("match", {}).get("where", [])
            filtered = _filter_df(events, where)
            for _, ev in filtered.iterrows():
                alerts.append({
                    "rule_id": rid,
                    "title": title,
                    "severity": severity,
                    "timestamp_start": ev["timestamp"],
                    "timestamp_end": ev["timestamp"],
                    "user": ev.get("user"),
                    "source_ip": ev.get("source_ip"),
                    "count": 1,
                    "sample_events": title,
                })

        elif rtype == "threshold":
            conf = r.get("threshold", {})
            where = conf.get("where", [])
            group_by = conf.get("group_by", ["user"])
            window_minutes = int(conf.get("window_minutes", 15))
            count_gte = int(conf.get("count_gte", 5))

            filtered = _filter_df(events, where).copy()
            if filtered.empty:
                continue
            # time window bucket
            filtered["window_start"] = filtered["timestamp"].dt.floor(f"{window_minutes}T")
            gb_cols = ["window_start"] + group_by
            agg = filtered.groupby(gb_cols).size().reset_index(name="n")
            hits = agg[agg["n"] >= count_gte]
            for _, h in hits.iterrows():
                # Build a context filter for sample extraction
                mask = filtered["window_start"] == h["window_start"]
                for gcol in group_by:
                    mask &= filtered[gcol].astype(str) == str(h[gcol])
                sample = filtered[mask].head(3)
                alerts.append({
                    "rule_id": rid,
                    "title": title,
                    "severity": severity,
                    "timestamp_start": h["window_start"],
                    "timestamp_end": h["window_start"],  # simplified
                    "user": h.get("user") if "user" in group_by else None,
                    "source_ip": h.get("source_ip") if "source_ip" in group_by else None,
                    "count": int(h["n"]),
                    "sample_events": "; ".join(sample["event"].astype(str).tolist()),
                })
        else:
            # Unknown rule type -> skip
            continue

    if not alerts:
        return pd.DataFrame(columns=[
            "rule_id", "title", "severity", "timestamp_start", "timestamp_end", "user", "source_ip", "count", "sample_events"
        ])
    df_alerts = pd.DataFrame(alerts)
    # order columns
    cols = ["rule_id", "title", "severity", "timestamp_start", "timestamp_end", "user", "source_ip", "count", "sample_events"]
    return df_alerts[cols].sort_values(["severity", "rule_id", "timestamp_start"], ascending=[True, True, True])