from pathlib import Path
from typing import Optional
import json

import typer
from rich.console import Console
from rich.table import Table

from detlab.analytics import generate_json_analytics, generate_markdown_analytics
from detlab.attck import build_technique_map
from detlab.dashboard import generate_dashboard
from detlab.eql import export_eql_detection, export_eql_directory
from detlab.kql import export_kql_detection, export_kql_directory
from detlab.navigator import generate_navigator_layer
from detlab.packs import generate_pack_report, render_pack_report_json, render_pack_report_markdown
from detlab.reporting import generate_json_report, generate_markdown_report, write_report
from detlab.scoring import generate_json_score_report, generate_markdown_score_report
from detlab.sigma import import_sigma_dir
from detlab.sigma_export import export_sigma_detection, export_sigma_directory
from detlab.splunk import export_splunk_detection, export_splunk_directory
from detlab.validators import load_detection_file, load_detection_dir

VERSION = "0.1.0"

app = typer.Typer(help="DetLab - Detection Engineering Workbench")
attack_app = typer.Typer(help="ATT&CK coverage analysis commands")
app.add_typer(attack_app, name="attack")
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



def _load_valid_detections(path: Path):
    _, valid, _ = load_detection_dir(path)
    if not valid:
        raise typer.Exit(code=1)
    return [load_detection_file(p) for p in path.rglob("*.y*ml")]



def _render_export_table(title: str, outputs: list[Path]) -> None:
    table = Table(title=title)
    table.add_column("Export File")
    for output in outputs:
        table.add_row(str(output))
    console.print(table)


@app.command("dashboard")
def dashboard(
    path: Path = typer.Argument(Path("detections")),
    output: Path = typer.Option(Path("reports/dashboard.html"), "--output", "-o"),
) -> None:
    detections = _load_valid_detections(path)
    content = generate_dashboard(detections)
    write_report(str(output), content)
    console.print(f"[green]Dashboard written to[/green] {output}")


@app.command("analytics")
def analytics(
    path: Path = typer.Argument(Path("detections")),
    format: str = typer.Option("markdown", "--format"),
    output: Path = typer.Option(Path("reports/analytics.md"), "--output", "-o"),
) -> None:
    detections = _load_valid_detections(path)

    if format == "markdown":
        content = generate_markdown_analytics(detections)
    elif format == "json":
        content = generate_json_analytics(detections)
    else:
        raise typer.Exit(code=1)

    write_report(str(output), content)
    console.print(f"[green]Analytics report written to[/green] {output}")


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


@app.command("score")
def score(
    path: Path = typer.Argument(Path("detections")),
    format: str = typer.Option("markdown", "--format"),
    output: Path = typer.Option(Path("reports/maturity.md"), "--output", "-o"),
) -> None:
    detections = _load_valid_detections(path)

    if format == "markdown":
        content = generate_markdown_score_report(detections)
    elif format == "json":
        content = generate_json_score_report(detections)
    else:
        raise typer.Exit(code=1)

    write_report(str(output), content)
    console.print(f"[green]Score report written to[/green] {output}")


@app.command("map-attck")
def map_attck(
    path: Path = typer.Argument(Path("detections")),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    detections = _load_valid_detections(path)
    mapping = build_technique_map(detections)
    rendered = json.dumps(mapping, indent=2)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        console.print(rendered)


@attack_app.command("report")
def attack_report(
    path: Path = typer.Argument(Path("detections")),
    format: str = typer.Option("markdown", "--format"),
    output: Path = typer.Option(Path("reports/attack-coverage.md"), "--output", "-o"),
) -> None:
    detections = _load_valid_detections(path)

    if format == "markdown":
        content = generate_markdown_analytics(detections)
    elif format == "json":
        content = generate_json_analytics(detections)
    else:
        raise typer.Exit(code=1)

    write_report(str(output), content)
    console.print(f"[green]ATT&CK report written to[/green] {output}")


@app.command("sigma-import")
def sigma_import(
    input_dir: Path = typer.Argument(Path("sigma_rules")),
    output_dir: Path = typer.Option(Path("detections/imported"), "--output", "-o"),
    start_id: int = typer.Option(1000, "--start-id"),
) -> None:
    outputs = import_sigma_dir(input_dir, output_dir, start_id)
    _render_export_table("Sigma Import Results", outputs)


@app.command("convert")
def convert(
    source: Path = typer.Argument(..., help="Detection file or directory to convert."),
    target: str = typer.Option(..., "--target", help="Target backend: sigma, splunk, kql, eql."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    target = target.lower()
    extension_map = {
        "sigma": ".yml",
        "splunk": ".spl",
        "kql": ".kql",
        "eql": ".eql",
    }

    if target not in extension_map:
        console.print(f"[red]Unsupported target:[/red] {target}")
        raise typer.Exit(code=1)

    if source.is_dir():
        output_dir = output or Path(f"exports/{target}")
        if target == "sigma":
            outputs = export_sigma_directory(_load_valid_detections(source), output_dir)
        elif target == "splunk":
            outputs = export_splunk_directory(_load_valid_detections(source), output_dir)
        elif target == "kql":
            outputs = export_kql_directory(_load_valid_detections(source), output_dir)
        else:
            outputs = export_eql_directory(_load_valid_detections(source), output_dir)
        _render_export_table(f"{target.upper()} Conversion Results", outputs)
        return

    detection = load_detection_file(source)
    rendered = {
        "sigma": export_sigma_detection(detection),
        "splunk": export_splunk_detection(detection),
        "kql": export_kql_detection(detection),
        "eql": export_eql_detection(detection),
    }[target]

    output_path = output or Path(f"exports/{source.stem}{extension_map[target]}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    console.print(f"[green]Converted detection written to[/green] {output_path}")


@app.command("export-sigma")
def export_sigma(
    path: Path = typer.Argument(Path("detections")),
    output_dir: Path = typer.Option(Path("exports/sigma"), "--output", "-o"),
) -> None:
    outputs = export_sigma_directory(_load_valid_detections(path), output_dir)
    _render_export_table("Sigma Export Results", outputs)


@app.command("export-splunk")
def export_splunk(
    path: Path = typer.Argument(Path("detections")),
    output_dir: Path = typer.Option(Path("exports/splunk"), "--output", "-o"),
) -> None:
    outputs = export_splunk_directory(_load_valid_detections(path), output_dir)
    _render_export_table("Splunk Export Results", outputs)


@app.command("export-kql")
def export_kql(
    path: Path = typer.Argument(Path("detections")),
    output_dir: Path = typer.Option(Path("exports/kql"), "--output", "-o"),
) -> None:
    outputs = export_kql_directory(_load_valid_detections(path), output_dir)
    _render_export_table("KQL Export Results", outputs)


@app.command("export-eql")
def export_eql(
    path: Path = typer.Argument(Path("detections")),
    output_dir: Path = typer.Option(Path("exports/eql"), "--output", "-o"),
) -> None:
    outputs = export_eql_directory(_load_valid_detections(path), output_dir)
    _render_export_table("EQL Export Results", outputs)


@app.command("pack-report")
def pack_report(
    pack_dir: Path = typer.Argument(..., help="Path to a detection pack directory."),
    format: str = typer.Option("markdown", "--format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    report = generate_pack_report(pack_dir)
    if format == "markdown":
        content = render_pack_report_markdown(report)
    elif format == "json":
        content = render_pack_report_json(report)
    else:
        raise typer.Exit(code=1)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Pack report written to[/green] {output}")
        return

    console.print(content)


@app.command()
def navigator(
    path: Path = typer.Argument(Path("detections")),
    output: Path = typer.Option(Path("reports/navigator.json"), "--output", "-o"),
    score_by: str = typer.Option("severity", "--score-by"),
) -> None:
    detections = _load_valid_detections(path)
    content = generate_navigator_layer(detections, score_by=score_by)
    write_report(str(output), content)


@app.command()
def report(
    path: Path = typer.Argument(Path("detections")),
    format: str = typer.Option("markdown", "--format"),
    output: Path = typer.Option(Path("reports/coverage.md"), "--output", "-o"),
) -> None:
    detections = _load_valid_detections(path)

    if format == "markdown":
        content = generate_markdown_report(detections)
    elif format == "json":
        content = generate_json_report(detections)
    else:
        raise typer.Exit(code=1)

    write_report(str(output), content)


if __name__ == "__main__":
    app()
