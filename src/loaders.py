from pathlib import Path
import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "product", "category", "event", "result", "user", "source_ip", "tcode", "details"
]

def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    # Ensure all required columns exist
    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            df[col] = None
    # Parse timestamps
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df[REQUIRED_COLUMNS]

def load_streams(streams_dir: Path) -> pd.DataFrame:
    """
    Load all CSV streams under streams_dir into a single DataFrame.
    """
    files = sorted(Path(streams_dir).glob("*.csv"))
    frames = []
    for f in files:
        df = pd.read_csv(f)
        df = _normalize_columns(df)
        frames.append(df)
    if not frames:
        return pd.DataFrame(columns=REQUIRED_COLUMNS)
    return pd.concat(frames, ignore_index=True).dropna(subset=["timestamp"])