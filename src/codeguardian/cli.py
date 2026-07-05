"""
CodeGuardian CLI — command-line interface for AI code trust verification.

Usage:
    codeguardian review <file>
    codeguardian scan <directory>
    codeguardian score <file>
    codeguardian batch <directory>
    codeguardian verify <file>
    codeguardian deps <manifest>
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from codeguardian.core.reviewer import CodeReviewer
from codeguardian.core.scanner import SecurityScanner
from codeguardian.core.trust_scorer import TrustScorer
from codeguardian.core.trust_engine import TrustEngine
from codeguardian.core.dependency_analyzer import DependencyAnalyzer

app = typer.Typer(
    name="codeguardian",
    help="CodeGuardian — AI Code Trust Verification Platform",
    add_completion=False,
)
console = Console()


@app.command()
def review(
    file_path: str = typer.Argument(..., help="File path to review"),
    context: Optional[str] = typer.Option(None, "--context", "-c", help="Business context or architecture doc"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output in JSON format"),
):
    """Review a single file and generate a trust report."""
    p = Path(file_path)
    if not p.exists():
        console.print(f"[red]Error:[/red] File not found: {file_path}")
        raise typer.Exit(code=1)

    async def _run():
        reviewer = CodeReviewer()
        return await reviewer.review(file_path, context=context or "")

    with console.status(f"[bold blue]Reviewing {p.name}..."):
        report = asyncio.run(_run())

    if json_output:
        console.print_json(report.model_dump_json(indent=2))
    else:
        _display_report(report)


@app.command()
def scan(
    directory: str = typer.Argument(".", help="Directory to scan"),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", help="Recursively scan subdirectories"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output in JSON format"),
):
    """Scan a directory for security vulnerabilities."""
    p = Path(directory)
    if not p.exists():
        console.print(f"[red]Error:[/red] Directory not found: {directory}")
        raise typer.Exit(code=1)

    with console.status(f"[bold blue]Scanning {directory}..."):
        scanner = SecurityScanner()
        vulns = scanner.scan_directory(directory, recursive=recursive)

    if json_output:
        console.print_json(json.dumps([v.model_dump() for v in vulns], indent=2))
    else:
        _display_vulnerabilities(vulns, directory)
        console.print(f"\n[bold]Total: {len(vulns)} vulnerabilities found[/bold]")


@app.command()
def score(
    file_path: str = typer.Argument(..., help="File path to score"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output in JSON format"),
):
    """Compute a trust score for a file (quick mode, no full review)."""
    p = Path(file_path)
    if not p.exists():
        console.print(f"[red]Error:[/red] File not found: {file_path}")
        raise typer.Exit(code=1)

    async def _run():
        reviewer = CodeReviewer()
        return await reviewer.review(file_path)

    with console.status(f"[bold blue]Scoring {p.name}..."):
        report = asyncio.run(_run())

    score = report.trust_score
    color = "green" if score.overall >= 80 else "yellow" if score.overall >= 60 else "red"

    if json_output:
        console.print_json(score.model_dump_json(indent=2))
    else:
        console.print(Panel.fit(
            f"[bold {color}]{score.overall}/100[/bold {color}] — Grade: [bold {color}]{score.grade}[/bold {color}]\n\n"
            f"Security: {score.security_score}/100  |  Correctness: {score.correctness_score}/100\n"
            f"Consistency: {score.consistency_score}/100  |  Hallucination Risk: {score.hallucination_risk}/100\n"
            f"Dependency Risk: {score.dependency_risk}/100\n\n"
            f"[italic]{score.comment}[/italic]",
            title=f"Trust Score — {p.name}",
            border_style=color,
        ))


@app.command()
def batch(
    directory: str = typer.Argument(..., help="Directory containing code files to review"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file path"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output in JSON format"),
):
    """Review all code files in a directory and generate a batch report."""
    p = Path(directory)
    if not p.exists():
        console.print(f"[red]Error:[/red] Directory not found: {directory}")
        raise typer.Exit(code=1)

    async def _run():
        reviewer = CodeReviewer()
        return await reviewer.review_directory(directory)

    with console.status(f"[bold blue]Reviewing files in {directory}..."):
        reports = asyncio.run(_run())

    if json_output:
        data = [r.model_dump() for r in reports]
        console.print_json(json.dumps(data, indent=2))
    else:
        _display_batch_summary(reports, directory)

    if output:
        data = [r.model_dump() for r in reports]
        Path(output).write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"\n[green]Report saved to: {output}[/green]")


@app.command()
def verify(
    file_path: str = typer.Argument(..., help="File path to verify"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI review (faster, offline-safe)"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output in JSON format"),
):
    """Full trust verification pipeline: deps + scan + review + score."""
    p = Path(file_path)
    if not p.exists():
        console.print(f"[red]Error:[/red] File not found: {file_path}")
        raise typer.Exit(code=1)

    async def _run():
        engine = TrustEngine(enable_ai_review=not no_ai)
        return await engine.verify(p)

    with console.status(f"[bold blue]Verifying {p.name}..."):
        result = asyncio.run(_run())

    if json_output:
        console.print_json(json.dumps(result.summary, indent=2))
    else:
        ts = result.trust_score
        color = "green" if ts and ts.overall >= 80 else "yellow" if ts and ts.overall >= 60 else "red"
        console.print(Panel.fit(
            f"[bold {color}]{ts.overall if ts else 'N/A'}/100[/bold {color}] — Grade: [bold {color}]{ts.grade if ts else 'N/A'}[/bold {color}]\n\n"
            f"Vulnerabilities: {len(result.vulnerabilities)} (critical: {result.critical_count})\n"
            f"Dependency Issues: {result.dependency_report.vulnerable_count if result.dependency_report else 0}\n"
            f"Duration: {result.duration_ms:.0f}ms",
            title=f"Trust Verification — {p.name}",
            border_style=color,
        ))


@app.command()
def deps(
    manifest: str = typer.Argument(..., help="Path to dependency manifest (requirements.txt, pyproject.toml, package.json, etc.)"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output in JSON format"),
):
    """Analyze a dependency manifest for known vulnerabilities."""
    p = Path(manifest)
    if not p.exists():
        console.print(f"[red]Error:[/red] File not found: {manifest}")
        raise typer.Exit(code=1)

    async def _run():
        analyzer = DependencyAnalyzer()
        return await analyzer.analyze(p)

    with console.status(f"[bold blue]Analyzing dependencies in {p.name}..."):
        report = asyncio.run(_run())

    if json_output:
        data = {
            "summary": report.summary,
            "entries": [
                {
                    "name": e.name,
                    "version": e.version,
                    "risk": e.highest_risk.value,
                    "issues": [{"cve": i.cve_id, "title": i.title, "risk": i.risk.value} for i in e.issues],
                }
                for e in report.entries
                if e.issues
            ],
        }
        console.print_json(json.dumps(data, indent=2))
    else:
        if not report.entries:
            console.print("[yellow]No dependencies found in this file.[/yellow]")
            return

        table = Table(title=f"Dependency Analysis — {p.name}")
        table.add_column("Package", style="bold")
        table.add_column("Version")
        table.add_column("Risk")
        table.add_column("Issues")

        risk_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
            "clean": "green",
        }

        for entry in report.entries:
            risk = entry.highest_risk.value
            color = risk_colors.get(risk, "white")
            issue_count = len(entry.issues)
            table.add_row(
                entry.name,
                entry.version,
                f"[{color}]{risk}[/{color}]",
                str(issue_count) if issue_count else "-",
            )

        console.print(table)
        s = report.summary
        console.print(f"\n[bold]Summary:[/bold] {s['total']} deps, {s['vulnerable']} vulnerable ({s['critical']} critical), pass rate: {s['pass_rate']}%")


@app.command()
def version():
    """Display CodeGuardian version."""
    from codeguardian import __version__
    console.print(f"CodeGuardian v{__version__}")


# ── Display Helpers ────────────────────────────────────────────────

def _display_report(report) -> None:
    """Display a review report in a rich format."""
    score = report.trust_score
    color = "green" if score.overall >= 80 else "yellow" if score.overall >= 60 else "red"

    # Trust score panel
    console.print(Panel.fit(
        f"[bold {color}]{score.overall}/100[/bold {color}] — Grade: [bold {color}]{score.grade}[/bold {color}]\n"
        f"Security: {score.security_score} | Correctness: {score.correctness_score} | "
        f"Consistency: {score.consistency_score} | Hallucination Risk: {score.hallucination_risk}",
        title=f"Trust Score — {report.target}",
        border_style=color,
    ))

    # Findings table
    all_items = list(report.findings) + list(report.vulnerabilities)
    if all_items:
        table = Table(title=f"Findings ({len(all_items)} total)")
        table.add_column("Severity", style="bold")
        table.add_column("Category")
        table.add_column("Title")
        table.add_column("Suggestion")

        severity_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }

        for item in all_items[:20]:
            sev = item.severity.value
            cat = getattr(item, "category", None)
            cat_val = cat.value if hasattr(cat, "value") else str(cat) if cat else "-"
            title = getattr(item, "title", "")
            suggestion = getattr(item, "suggestion", getattr(item, "recommendation", ""))

            table.add_row(
                f"[{severity_colors.get(sev, 'white')}]{sev}[/{severity_colors.get(sev, 'white')}]",
                cat_val,
                title[:60],
                suggestion[:60],
            )

        console.print(table)

    # Summary
    console.print(f"\n[bold]Summary:[/bold] {report.summary}")
    if report.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            console.print(f"  - {rec}")


def _display_vulnerabilities(vulns, directory: str) -> None:
    """Display vulnerabilities in a table."""
    if not vulns:
        console.print(f"[green]No vulnerabilities found in {directory}[/green]")
        return

    table = Table(title=f"Vulnerabilities in {directory}")
    table.add_column("Severity", style="bold")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("File")
    table.add_column("Line")

    severity_colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "green",
        "info": "blue",
    }

    for v in vulns:
        table.add_row(
            f"[{severity_colors.get(v.severity.value, 'white')}]{v.severity.value}[/{severity_colors.get(v.severity.value, 'white')}]",
            v.id,
            v.title[:50],
            v.file_path[:40] if v.file_path else "-",
            str(v.line_start),
        )

    console.print(table)


def _display_batch_summary(reports, directory: str) -> None:
    """Display batch review summary."""
    if not reports:
        console.print(f"[yellow]No code files found in {directory}[/yellow]")
        return

    avg_score = sum(r.trust_score.overall for r in reports) / len(reports)
    total_findings = sum(r.finding_count for r in reports)

    table = Table(title=f"Batch Review — {directory} ({len(reports)} files)")
    table.add_column("File")
    table.add_column("Trust Score")
    table.add_column("Grade")
    table.add_column("Findings")

    for r in reports:
        color = "green" if r.trust_score.overall >= 80 else "yellow" if r.trust_score.overall >= 60 else "red"
        table.add_row(
            r.target[:50],
            f"[{color}]{r.trust_score.overall}/100[/{color}]",
            f"[{color}]{r.trust_score.grade}[/{color}]",
            str(r.finding_count),
        )

    console.print(table)
    color = "green" if avg_score >= 80 else "yellow" if avg_score >= 60 else "red"
    console.print(f"\nAverage Trust Score: [{color}]{avg_score:.1f}/100[/{color}] | Total Findings: {total_findings}")


if __name__ == "__main__":
    app()
