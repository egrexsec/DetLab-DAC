from pathlib import Path
from typing import Optional
import json

import typer
from rich.console import Console
from rich.table import Table

from detlab.attck import build_technique_map
from detlab.navigator import generate_navigator_layer
from detlab.reporting import generate_json_report, generate_markdown_report, write_report
from detlab.sigma import import_sigma_dir
from detlab.validators import load_detection_file, load_detection_dir

VERSION = "0.1.0"

app = typer.Typer(help="DetLab - detection-as-code validation and ATT&CK reporting")
console = Console()


def version_callback(value: bool):
    if value:
        console.print(f"DetLab version: {VERSION}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True, help="Show version and exit."
    )
):
    return


@app.command()
def validate(
    path: Path = typer.Argument(
        Path("detections"),
        exists=False,
        readable=True,
        resolve_path=False,
        help="Path to the detections directory.",
    )
) -> None:
    files, valid, errors = load_detection_dir(path)

    table = Table(title="Validation Results")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Details")

    for file in files:
        if file in errors:
            table.add_row(str(file), "[red]FAIL[/red]", errors[file])
        else:
            table.add_row(str(file), "[green]PASS[/green]", "Valid detection")

    console.print(table)

    if not valid:
        raise typer.Exit(code=1)


@app.command("map-attck")
def map_attck(
    path: Path = typer.Argument(
        Path("detections"),
        exists=False,
        readable=True,
        resolve_path=False,
        help="Path to the detections directory.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write ATT&CK mapping to a JSON file.",
    ),
) -> None:
    _, valid, errors = load_detection_dir(path)
    if not valid:
        for file, err in errors.items():
            console.print(f"[red]{file}[/red]: {err}")
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in path.rglob("*.y*ml")]
    mapping = build_technique_map(detections)
    rendered = json.dumps(mapping, indent=2)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote ATT&CK mapping to[/green] {output}")
    else:
        console.print(rendered)


@app.command()
def sigma_import(
    input_dir: Path = typer.Argument(
        Path("sigma_rules"),
        exists=False,
        readable=True,
        resolve_path=False,
        help="Path to Sigma rules directory.",
    ),
    output_dir: Path = typer.Option(
        Path("detections/imported"),
        "--output",
        "-o",
        help="Output directory for converted detections.",
    ),
    start_id: int = typer.Option(
        1000,
        "--start-id",
        help="Starting numeric value for generated DET IDs.",
    ),
) -> None:
    outputs = import_sigma_dir(input_dir, output_dir, start_id)

    table = Table(title="Sigma Import Results")
    table.add_column("Sigma Rule")
    table.add_column("Output Detection")

    for output in outputs:
        table.add_row(output.stem, str(output))

    console.print(table)
    console.print(f"[green]Imported {len(outputs)} Sigma rules[/green]")


@app.command()
def navigator(
    path: Path = typer.Argument(
        Path("detections"),
        exists=False,
        readable=True,
        resolve_path=False,
        help="Path to the detections directory.",
    ),
    output: Path = typer.Option(
        Path("reports/navigator.json"),
        "--output",
        "-o",
        help="Output ATT&CK Navigator layer file.",
    ),
    score_by: str = typer.Option(
        "severity",
        "--score-by",
        help="Scoring mode: severity or count.",
    ),
) -> None:
    _, valid, errors = load_detection_dir(path)
    if not valid:
        for file, err in errors.items():
            console.print(f"[red]{file}[/red]: {err}")
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in path.rglob("*.y*ml")]

    content = generate_navigator_layer(detections, score_by=score_by)

    write_report(str(output), content)
    console.print(f"[green]Navigator layer written to[/green] {output}")


@app.command()
def report(
    path: Path = typer.Argument(
        Path("detections"),
        exists=False,
        readable=True,
        resolve_path=False,
        help="Path to the detections directory.",
    ),
    format: str = typer.Option(
        "markdown",
        "--format",
        help="Output format: markdown or json.",
    ),
    output: Path = typer.Option(
        Path("reports/coverage.md"),
        "--output",
        "-o",
        help="Output file path.",
    ),
) -> None:
    _, valid, errors = load_detection_dir(path)
    if not valid:
        for file, err in errors.items():
            console.print(f"[red]{file}[/red]: {err}")
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in path.rglob("*.y*ml")]

    if format == "markdown":
        content = generate_markdown_report(detections)
    elif format == "json":
        content = generate_json_report(detections)
    else:
        console.print("[red]Unsupported format. Use 'markdown' or 'json'.[/red]")
        raise typer.Exit(code=1)

    write_report(str(output), content)
    console.print(f"[green]Report written to[/green] {output}")


if __name__ == "__main__":
    app()
