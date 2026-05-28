from pathlib import Path
from typing import Optional
import json

import typer
from rich.console import Console
from rich.table import Table

from detlab.attck import build_technique_map
from detlab.kql import export_kql_directory
from detlab.navigator import generate_navigator_layer
from detlab.reporting import generate_json_report, generate_markdown_report, write_report
from detlab.sigma import import_sigma_dir
from detlab.splunk import export_splunk_directory
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
def validate(path: Path = typer.Argument(Path("detections"))) -> None:
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
    path: Path = typer.Argument(Path("detections")),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    _, valid, _ = load_detection_dir(path)

    if not valid:
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in path.rglob("*.y*ml")]
    mapping = build_technique_map(detections)
    rendered = json.dumps(mapping, indent=2)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        console.print(rendered)


@app.command("sigma-import")
def sigma_import(
    input_dir: Path = typer.Argument(Path("sigma_rules")),
    output_dir: Path = typer.Option(Path("detections/imported"), "--output", "-o"),
    start_id: int = typer.Option(1000, "--start-id"),
) -> None:
    outputs = import_sigma_dir(input_dir, output_dir, start_id)

    table = Table(title="Sigma Import Results")
    table.add_column("Output Detection")

    for output in outputs:
        table.add_row(str(output))

    console.print(table)


@app.command("export-splunk")
def export_splunk(
    path: Path = typer.Argument(Path("detections")),
    output_dir: Path = typer.Option(Path("exports/splunk"), "--output", "-o"),
) -> None:
    _, valid, errors = load_detection_dir(path)

    if not valid:
        for file, err in errors.items():
            console.print(f"[red]{file}[/red]: {err}")
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in path.rglob("*.y*ml")]
    outputs = export_splunk_directory(detections, output_dir)

    table = Table(title="Splunk Export Results")
    table.add_column("Export File")

    for output in outputs:
        table.add_row(str(output))

    console.print(table)


@app.command("export-kql")
def export_kql(
    path: Path = typer.Argument(Path("detections")),
    output_dir: Path = typer.Option(Path("exports/kql"), "--output", "-o"),
) -> None:
    _, valid, errors = load_detection_dir(path)

    if not valid:
        for file, err in errors.items():
            console.print(f"[red]{file}[/red]: {err}")
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in path.rglob("*.y*ml")]
    outputs = export_kql_directory(detections, output_dir)

    table = Table(title="KQL Export Results")
    table.add_column("Export File")

    for output in outputs:
        table.add_row(str(output))

    console.print(table)
    console.print(f"[green]Exported {len(outputs)} KQL queries[/green]")


@app.command()
def navigator(
    path: Path = typer.Argument(Path("detections")),
    output: Path = typer.Option(Path("reports/navigator.json"), "--output", "-o"),
    score_by: str = typer.Option("severity", "--score-by"),
) -> None:
    _, valid, _ = load_detection_dir(path)

    if not valid:
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in path.rglob("*.y*ml")]
    content = generate_navigator_layer(detections, score_by=score_by)

    write_report(str(output), content)


@app.command()
def report(
    path: Path = typer.Argument(Path("detections")),
    format: str = typer.Option("markdown", "--format"),
    output: Path = typer.Option(Path("reports/coverage.md"), "--output", "-o"),
) -> None:
    _, valid, _ = load_detection_dir(path)

    if not valid:
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in path.rglob("*.y*ml")]

    if format == "markdown":
        content = generate_markdown_report(detections)
    elif format == "json":
        content = generate_json_report(detections)
    else:
        raise typer.Exit(code=1)

    write_report(str(output), content)


if __name__ == "__main__":
    app()
