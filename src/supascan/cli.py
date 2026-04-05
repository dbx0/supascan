from __future__ import annotations
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
import requests
from rich.console import Console
from rich.table import Table as RichTable
from rich.text import Text

from . import cache as cache_mod
from .client import SupabaseClient
from .discovery import find_edge_functions, from_har_file, from_html_file, from_js_file, from_url
from .enumeration import enumerate_buckets, enumerate_rpc_functions, enumerate_tables
from .models import AuditReport, Credentials, Finding, Severity
from .testing import run_all_passive_checks
from .write_testing import run_write_tests

console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    Severity.critical: "bold red",
    Severity.high: "red",
    Severity.medium: "yellow",
    Severity.low: "cyan",
    Severity.info: "dim",
}


def _severity_text(s: Severity) -> Text:
    return Text(s.value.upper(), style=SEVERITY_COLORS.get(s, "white"))


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("[green]No findings.[/green]")
        return
    t = RichTable(title="Findings", show_lines=True)
    t.add_column("Severity", style="bold")
    t.add_column("Type")
    t.add_column("Description")
    for f in findings:
        t.add_row(_severity_text(f.severity), f.title, f.description)
    console.print(t)


_RISK_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def report_to_dict(report: AuditReport) -> dict:
    def finding_to_dict(f):
        return {
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "affected_resource": f.affected_resource,
            "recommendation": f.recommendation,
            "evidence": f.evidence,
        }

    # Summary counts
    summary = {s: 0 for s in _RISK_WEIGHTS}
    for f in report.findings:
        summary[f.severity.value] += 1

    risk_score = sum(_RISK_WEIGHTS[s] * count for s, count in summary.items())

    return {
        "project_ref": report.target,
        "url": f"https://{report.target}.supabase.co",
        "summary": summary,
        "risk_score": risk_score,
        "findings": [finding_to_dict(f) for f in report.findings],
    }


def _write_output(output: Optional[str], report: AuditReport) -> None:
    if not output:
        return
    data = report_to_dict(report)
    Path(output).write_text(json.dumps(data, indent=2))
    console.print(f"[green]Report written to {output}[/green]")


def _get_client(ctx: click.Context, require_creds: bool = True) -> Optional[SupabaseClient]:
    project_ref = ctx.obj.get("project_ref")
    anon_key = ctx.obj.get("anon_key")
    verbose = ctx.obj.get("verbose", False)

    if project_ref and not anon_key:
        cached = cache_mod.get_credentials(project_ref)
        if cached:
            anon_key = cached.anon_key
            console.print(f"[dim]Using cached anon key for {project_ref}[/dim]")

    if not project_ref or not anon_key:
        if require_creds:
            console.print("[red]Error: --project-ref and --anon-key are required.[/red]")
            sys.exit(1)
        return None

    creds = Credentials(project_ref=project_ref, anon_key=anon_key)
    return SupabaseClient(creds, verbose=verbose)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Root CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.option("--project-ref", "-p", envvar="SUPABASE_PROJECT_REF", default=None)
@click.option("--anon-key", "-k", envvar="SUPABASE_ANON_KEY", default=None)
@click.option("--output", "-o", default=None, help="Write JSON report to this file")
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.pass_context
def cli(ctx, project_ref, anon_key, output, verbose):
    """supascan — Supabase security auditing tool."""
    ctx.ensure_object(dict)
    ctx.obj["project_ref"] = project_ref
    ctx.obj["anon_key"] = anon_key
    ctx.obj["output"] = output
    ctx.obj["verbose"] = verbose


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("target")
@click.option("--type", "target_type", type=click.Choice(["url", "html", "js", "har", "auto"]), default="auto")
@click.option("--save/--no-save", default=True, help="Save discovered credentials to cache")
@click.pass_context
def discover(ctx, target, target_type, save):
    """Discover Supabase credentials from a URL or file."""
    creds = None

    if target_type == "auto":
        if target.startswith("http://") or target.startswith("https://"):
            target_type = "url"
        elif target.endswith(".har"):
            target_type = "har"
        elif target.endswith(".js"):
            target_type = "js"
        else:
            target_type = "html"

    console.print(f"[bold]Discovering credentials from {target_type}: {target}[/bold]")

    if target_type == "url":
        creds = from_url(target)
    elif target_type == "html":
        creds = from_html_file(target)
    elif target_type == "js":
        creds = from_js_file(target)
    elif target_type == "har":
        creds = from_har_file(target)

    if creds:
        console.print(f"[green]Found credentials![/green]")
        console.print(f"  Project ref: [bold]{creds.project_ref}[/bold]")
        console.print(f"  Anon key:    [bold]{creds.anon_key[:20]}...[/bold]")
        if save:
            cache_mod.add_credentials(creds)
            console.print(f"[dim]Saved to cache.[/dim]")
    else:
        console.print("[yellow]No Supabase credentials found.[/yellow]")

    output = ctx.obj.get("output")
    if output and creds:
        report = AuditReport(
            target=creds.project_ref,
            timestamp=_now_iso(),
            findings=[
                Finding(
                    severity=Severity.info,
                    type="credentials_discovered",
                    title="Supabase credentials found in public source",
                    description="Supabase project ref and anonymous API key were discovered in a publicly accessible resource.",
                    affected_resource=creds.source or "unknown",
                    recommendation="Rotate the exposed anonymous key in the Supabase dashboard and audit all public-facing assets.",
                    evidence={"project_ref": creds.project_ref, "source": creds.source},
                )
            ],
        )
        _write_output(output, report)


# ---------------------------------------------------------------------------
# enum
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--tables/--no-tables", default=True)
@click.option("--rpc/--no-rpc", default=True)
@click.option("--buckets/--no-buckets", default=True)
@click.pass_context
def enum(ctx, tables, rpc, buckets):
    """Enumerate Supabase resources (tables, RPCs, buckets)."""
    client = _get_client(ctx)
    output = ctx.obj.get("output")

    found_tables = []
    found_rpcs = []
    found_buckets = []

    if tables:
        console.print("[bold]Enumerating tables...[/bold]")
        found_tables = enumerate_tables(client)
        t = RichTable(title="Tables")
        t.add_column("Name")
        t.add_column("Accessible")
        t.add_column("Columns")
        t.add_column("Sample Rows")
        for tbl in found_tables:
            t.add_row(
                tbl.name,
                "[green]Yes[/green]" if tbl.accessible else "[red]No[/red]",
                str(len(tbl.columns)),
                str(len(tbl.sample_data)),
            )
        console.print(t)

    if rpc:
        console.print("[bold]Enumerating RPC functions...[/bold]")
        found_rpcs = enumerate_rpc_functions(client)
        if found_rpcs:
            t = RichTable(title="RPC Functions")
            t.add_column("Name")
            t.add_column("Accessible")
            t.add_column("Status")
            for fn in found_rpcs:
                t.add_row(
                    fn.name,
                    "[green]Yes[/green]" if fn.accessible else "[red]No[/red]",
                    str(fn.response_status),
                )
            console.print(t)
        else:
            console.print("[dim]No RPC functions found.[/dim]")

    if buckets:
        console.print("[bold]Enumerating storage buckets...[/bold]")
        found_buckets = enumerate_buckets(client)
        if found_buckets:
            t = RichTable(title="Storage Buckets")
            t.add_column("Name")
            t.add_column("Public")
            t.add_column("Accessible")
            t.add_column("Files")
            for b in found_buckets:
                t.add_row(
                    b.name,
                    "[red]Yes[/red]" if b.public else "No",
                    "[green]Yes[/green]" if b.accessible else "No",
                    str(b.file_count),
                )
            console.print(t)
        else:
            console.print("[dim]No storage buckets found.[/dim]")

    if output:
        report = AuditReport(
            target=ctx.obj.get("project_ref", "unknown"),
            timestamp=_now_iso(),
            tables=found_tables,
            rpc_functions=found_rpcs,
            buckets=found_buckets,
        )
        _write_output(output, report)


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("table")
@click.option("--limit", default=20, show_default=True)
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json")
@click.option("--anon/--no-anon", default=True)
@click.pass_context
def query(ctx, table, limit, fmt, anon):
    """Query a specific table."""
    client = _get_client(ctx)
    try:
        resp = client.query_table(table, limit=limit, csv=(fmt == "csv"), anon=anon)
    except requests.exceptions.ConnectionError:
        creds = ctx.obj["creds"]
        console.print(f"[red]Connection failed: could not resolve {creds.base_url}[/red]")
        console.print("[yellow]The Supabase project may be deleted, paused, or using a custom domain.[/yellow]")
        sys.exit(1)
    if resp.status_code == 200:
        if fmt == "csv":
            click.echo(resp.text)
        else:
            click.echo(json.dumps(resp.json(), indent=2))
    else:
        console.print(f"[red]Error {resp.status_code}: {resp.text[:200]}[/red]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# dump
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--tables", "table_names", multiple=True, help="Tables to dump (default: all accessible)")
@click.option("--out-dir", default=".", show_default=True)
@click.pass_context
def dump(ctx, table_names, out_dir):
    """Dump table data to JSON files."""
    client = _get_client(ctx)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not table_names:
        console.print("[bold]Discovering tables...[/bold]")
        try:
            tables = enumerate_tables(client)
        except requests.exceptions.ConnectionError:
            creds = ctx.obj["creds"]
            console.print(f"[red]Connection failed: could not resolve {creds.base_url}[/red]")
            console.print("[yellow]The Supabase project may be deleted, paused, or using a custom domain.[/yellow]")
            sys.exit(1)
        table_names = [t.name for t in tables if t.accessible]

    for name in table_names:
        console.print(f"  Dumping {name}...")
        try:
            resp = client.query_table(name, limit=10000)
        except requests.exceptions.ConnectionError:
            console.print(f"  [red]Connection lost while dumping {name}[/red]")
            sys.exit(1)
        if resp.status_code == 200:
            dest = out / f"{name}.json"
            dest.write_text(json.dumps(resp.json(), indent=2))
            console.print(f"  [green]Saved {dest}[/green]")
        else:
            console.print(f"  [red]Failed ({resp.status_code})[/red]")


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--rls", is_flag=True, default=False)
@click.option("--rpc", is_flag=True, default=False)
@click.option("--buckets", is_flag=True, default=False)
@click.option("--edge-functions", "edge_functions", multiple=True)
@click.option("--output", "-o", default=None, help="Write JSON report to this file")
@click.pass_context
def test(ctx, rls, rpc, buckets, edge_functions, output):
    """Run passive security checks."""
    client = _get_client(ctx)
    output = output or ctx.obj.get("output")

    run_all = not (rls or rpc or buckets or edge_functions)

    tables = []
    rpcs = []
    found_buckets = []

    if run_all or rls:
        console.print("[bold]Enumerating tables for RLS check...[/bold]")
        tables = enumerate_tables(client)

    if run_all or rpc:
        console.print("[bold]Enumerating RPC functions...[/bold]")
        rpcs = enumerate_rpc_functions(client)

    if run_all or buckets:
        console.print("[bold]Enumerating buckets...[/bold]")
        found_buckets = enumerate_buckets(client)

    edge_fn_names = list(edge_functions)

    console.print("[bold]Running passive checks...[/bold]")
    edge_fn_objects, findings = run_all_passive_checks(
        client, tables, rpcs, found_buckets, edge_fn_names
    )
    _print_findings(findings)

    if output:
        report = AuditReport(
            target=ctx.obj.get("project_ref", "unknown"),
            timestamp=_now_iso(),
            findings=findings,
            tables=tables,
            rpc_functions=rpcs,
            buckets=found_buckets,
            edge_functions=edge_fn_objects,
        )
        _write_output(output, report)


# ---------------------------------------------------------------------------
# test-write
# ---------------------------------------------------------------------------

@cli.command("test-write")
@click.option("--tables", "table_names", multiple=True)
@click.option("--dry-run", is_flag=True, default=False, help="Show what would be tested, do not execute")
@click.option("--output", "-o", default=None, help="Write JSON report to this file")
@click.pass_context
def test_write(ctx, table_names, dry_run, output):
    """Run active write tests (INSERT/UPDATE/DELETE)."""
    client = _get_client(ctx)
    output = output or ctx.obj.get("output")

    if dry_run:
        console.print("[yellow]Dry-run mode: no writes will be performed.[/yellow]")
        return

    if table_names:
        tables = [t for t in enumerate_tables(client) if t.name in table_names]
    else:
        console.print("[bold]Enumerating tables...[/bold]")
        tables = enumerate_tables(client)

    console.print(f"[bold]Running write tests on {len(tables)} table(s)...[/bold]")
    write_results, findings = run_write_tests(client, tables)

    t = RichTable(title="Write Test Results")
    t.add_column("Table")
    t.add_column("INSERT")
    t.add_column("UPDATE")
    t.add_column("DELETE")
    for wr in write_results:
        def _color(r):
            from .models import WriteResult
            if r == WriteResult.allowed:
                return f"[red]{r.value}[/red]"
            if r == WriteResult.possible:
                return f"[yellow]{r.value}[/yellow]"
            return f"[green]{r.value}[/green]"
        t.add_row(wr.table, _color(wr.insert_result), _color(wr.update_result), _color(wr.delete_result))
    console.print(t)

    _print_findings(findings)

    if output:
        report = AuditReport(
            target=ctx.obj.get("project_ref", "unknown"),
            timestamp=_now_iso(),
            findings=findings,
            tables=tables,
            write_results=write_results,
        )
        _write_output(output, report)


# ---------------------------------------------------------------------------
# check-jwt
# ---------------------------------------------------------------------------

@cli.command("check-jwt")
@click.argument("names", nargs=-1, required=True)
@click.pass_context
def check_jwt(ctx, names):
    """Decode and inspect JWT tokens."""
    import jwt as pyjwt
    for token in names:
        console.print(f"\n[bold]Token: {token[:30]}...[/bold]")
        try:
            payload = pyjwt.decode(token, options={"verify_signature": False})
            console.print(json.dumps(payload, indent=2, default=str))
            role = payload.get("role", "unknown")
            if role == "anon":
                console.print("[yellow]Role: anon (anonymous key)[/yellow]")
            elif role == "service_role":
                console.print("[red bold]Role: service_role (ADMIN KEY - HIGH RISK)[/red bold]")
            else:
                console.print(f"Role: {role}")
        except Exception as e:
            console.print(f"[red]Failed to decode: {e}[/red]")


# ---------------------------------------------------------------------------
# signup
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--email", required=True)
@click.option("--password", required=True)
@click.option("--save-token", is_flag=True, default=False)
@click.pass_context
def signup(ctx, email, password, save_token):
    """Create a new Supabase user account."""
    client = _get_client(ctx)
    resp = client.signup(email, password)
    if resp.status_code in (200, 201):
        console.print("[green]Signup successful![/green]")
        data = resp.json()
        token = data.get("access_token")
        if token:
            console.print(f"  access_token: [bold]{token[:30]}...[/bold]")
            if save_token:
                client.creds.user_token = token
                cache_mod.add_credentials(client.creds)
                console.print("[dim]Token saved to cache.[/dim]")
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        console.print(f"[red]Signup failed ({resp.status_code}): {resp.text[:200]}[/red]")


# ---------------------------------------------------------------------------
# all (full scan)
# ---------------------------------------------------------------------------

@cli.command("all")
@click.argument("target")
@click.option("--write", is_flag=True, default=False, help="Enable active write tests (INSERT/UPDATE/DELETE)")
@click.option("--skip-signup", is_flag=True, default=False)
@click.option("--output", "-o", default=None, help="Write JSON report to this file")
@click.pass_context
def run_all(ctx, target, write, skip_signup, output):
    """Full scan: discover credentials then run all checks. Write tests are skipped unless --write is passed."""
    output = output or ctx.obj.get("output")

    # Step 1: credentials
    project_ref = ctx.obj.get("project_ref")
    anon_key = ctx.obj.get("anon_key")

    if project_ref and not anon_key:
        cached = cache_mod.get_credentials(project_ref)
        if cached:
            anon_key = cached.anon_key
            console.print(f"[dim]Using cached anon key for {project_ref}[/dim]")

    if not (project_ref and anon_key):
        console.print(f"[bold]Step 1: Discovering credentials from {target}[/bold]")
        creds = None
        if target.startswith("http://") or target.startswith("https://"):
            creds = from_url(target)
        elif target.endswith(".har"):
            creds = from_har_file(target)
        elif target.endswith(".js"):
            creds = from_js_file(target)
        else:
            creds = from_html_file(target)

        if not creds:
            console.print("[red]Could not discover credentials. Aborting.[/red]")
            sys.exit(1)

        project_ref = creds.project_ref
        anon_key = creds.anon_key
        cache_mod.add_credentials(creds)
        console.print(f"  [green]Found: {project_ref}[/green]")
    else:
        creds = Credentials(project_ref=project_ref, anon_key=anon_key)

    client = SupabaseClient(creds, verbose=ctx.obj.get("verbose", False))

    # Step 2: enumerate
    console.print("[bold]Step 2: Enumerating resources...[/bold]")
    try:
        tables = enumerate_tables(client)
    except requests.exceptions.ConnectionError:
        console.print(f"[red]Connection failed: could not resolve {creds.base_url}[/red]")
        console.print("[yellow]The Supabase project may be deleted, paused, or using a custom domain.[/yellow]")
        sys.exit(1)
    rpcs = enumerate_rpc_functions(client)
    buckets = enumerate_buckets(client)

    # Step 3: passive checks
    console.print("[bold]Step 3: Passive security checks...[/bold]")
    edge_functions, findings = run_all_passive_checks(client, tables, rpcs, buckets, [])

    # Step 4: write tests (opt-in only)
    write_results = []
    if write:
        console.print("[bold]Step 4: Write tests...[/bold]")
        write_results, write_findings = run_write_tests(client, tables)
        findings.extend(write_findings)

    _print_findings(findings)

    report = AuditReport(
        target=project_ref,
        timestamp=_now_iso(),
        findings=findings,
        tables=tables,
        rpc_functions=rpcs,
        buckets=buckets,
        edge_functions=edge_functions,
        write_results=write_results,
    )

    if output:
        _write_output(output, report)
    else:
        click.echo(json.dumps(report_to_dict(report), indent=2))


# ---------------------------------------------------------------------------
# cached subgroup
# ---------------------------------------------------------------------------

@cli.group()
def cached():
    """Manage cached credentials."""
    pass


@cached.command("list")
def cached_list():
    """List all cached credentials."""
    all_creds = cache_mod.list_all()
    if not all_creds:
        console.print("[dim]No cached credentials.[/dim]")
        return
    t = RichTable(title="Cached Credentials")
    t.add_column("Project Ref")
    t.add_column("Anon Key (preview)")
    t.add_column("Has User Token")
    t.add_column("Source")
    for c in all_creds:
        t.add_row(
            c.project_ref,
            c.anon_key[:20] + "...",
            "[green]Yes[/green]" if c.user_token else "No",
            c.source or "-",
        )
    console.print(t)


@cached.command("remove")
@click.argument("ref")
def cached_remove(ref):
    """Remove a cached credential by project ref."""
    if cache_mod.remove(ref):
        console.print(f"[green]Removed {ref}[/green]")
    else:
        console.print(f"[yellow]Not found: {ref}[/yellow]")


@cached.command("clear")
def cached_clear():
    """Clear all cached credentials."""
    count = cache_mod.clear()
    console.print(f"[green]Cleared {count} entries.[/green]")
