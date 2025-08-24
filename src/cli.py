import typer
from rich.console import Console
from pathlib import Path
from src.loaders import load_streams
from src.engine import load_rules, run_rules

app = typer.Typer(no_args_is_help=True)
console = Console()

@app.command()
def run(streams: Path = typer.Option(Path("data/streams"), exists=True, help="Directory with CSV log streams"),
        rules: Path = typer.Option(Path("rules"), exists=True, help="Directory with YAML rules"),
        out: Path = typer.Option(Path("out"), help="Output directory")):
    """
    Run detections across provided streams and write alerts + summary.
    """
    out.mkdir(parents=True, exist_ok=True)
    df = load_streams(streams)
    rule_defs = load_rules(rules)
    alerts = run_rules(df, rule_defs)

    alerts_path = out / "alerts.csv"
    summary_path = out / "summary.txt"

    alerts.to_csv(alerts_path, index=False)

    by_sev = alerts.groupby("severity").size().to_dict() if not alerts.empty else {}
    lines = [
        f"Events processed: {len(df)}",
        f"Alerts: {len(alerts)}",
        f"By severity: {by_sev}",
        f"Rules triggered: {sorted(alerts['rule_id'].unique().tolist()) if not alerts.empty else []}",
    ]
    summary_path.write_text("\n".join(lines), encoding="utf-8")

    console.print(f"[green]Wrote[/green] {alerts_path}, {summary_path}")

if __name__ == "__main__":
    app()