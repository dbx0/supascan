from __future__ import annotations

from .client import SupabaseClient
from .models import (
    EdgeFunction,
    Finding,
    RPCFunction,
    Severity,
    StorageBucket,
    TableInfo,
)


def check_rls(tables: list[TableInfo]) -> list[Finding]:
    findings = []
    for table in tables:
        if table.accessible and table.sample_data:
            findings.append(
                Finding(
                    severity=Severity.high,
                    type="rls_disabled",
                    title=f"Table '{table.name}' accessible with anonymous key",
                    description=(
                        f"The table '{table.name}' returns data when queried with the anonymous API key. "
                        "This may indicate missing or misconfigured Row Level Security (RLS) policies."
                    ),
                    affected_resource=f"Table: {table.name}",
                    recommendation=(
                        f"Enable RLS on this table and create appropriate policies to restrict anonymous access. "
                        f"Use: ALTER TABLE {table.name} ENABLE ROW LEVEL SECURITY;"
                    ),
                    evidence={
                        "table": table.name,
                        "columns": sorted([c.name for c in table.columns]),
                        "row_count": len(table.sample_data),
                        "sample_data": table.sample_data[:1],
                    },
                )
            )
        elif table.accessible and not table.sample_data:
            findings.append(
                Finding(
                    severity=Severity.medium,
                    type="rls_possibly_disabled",
                    title=f"Table '{table.name}' responds to anonymous queries",
                    description=(
                        f"The table '{table.name}' is reachable with the anonymous key (HTTP 200) but returned no rows. "
                        "RLS may be enabled but policies could be overly permissive or misconfigured."
                    ),
                    affected_resource=f"Table: {table.name}",
                    recommendation=(
                        f"Verify that RLS is enabled and that policies correctly restrict anonymous access. "
                        f"Run: SELECT * FROM pg_policies WHERE tablename = '{table.name}';"
                    ),
                    evidence={
                        "table": table.name,
                        "columns": sorted([c.name for c in table.columns]),
                        "row_count": 0,
                    },
                )
            )
    return findings


def check_public_buckets(buckets: list[StorageBucket]) -> list[Finding]:
    findings = []
    for bucket in buckets:
        if bucket.public:
            findings.append(
                Finding(
                    severity=Severity.high,
                    type="public_storage_bucket",
                    title=f"Storage bucket '{bucket.name}' is publicly accessible",
                    description=(
                        f"The storage bucket '{bucket.name}' is configured as public, "
                        "meaning any unauthenticated user can list and download its files."
                    ),
                    affected_resource=f"Storage Bucket: {bucket.name}",
                    recommendation=(
                        f"Set the bucket to private unless public access is intentional. "
                        f"Review and restrict storage policies for bucket '{bucket.name}'."
                    ),
                    evidence={
                        "bucket": bucket.name,
                        "public": True,
                        "file_count": bucket.file_count,
                    },
                )
            )
        elif bucket.accessible:
            findings.append(
                Finding(
                    severity=Severity.medium,
                    type="accessible_storage_bucket",
                    title=f"Storage bucket '{bucket.name}' accessible with anonymous key",
                    description=(
                        f"The storage bucket '{bucket.name}' allows object listing with the anonymous API key, "
                        "even though it is not marked public."
                    ),
                    affected_resource=f"Storage Bucket: {bucket.name}",
                    recommendation=(
                        f"Review storage policies for bucket '{bucket.name}' and ensure anonymous "
                        "listing/download is intentional."
                    ),
                    evidence={
                        "bucket": bucket.name,
                        "public": False,
                        "file_count": bucket.file_count,
                    },
                )
            )
    return findings


def check_public_rpcs(rpcs: list[RPCFunction]) -> list[Finding]:
    findings = []
    for rpc in rpcs:
        if rpc.accessible:
            findings.append(
                Finding(
                    severity=Severity.medium,
                    type="public_rpc_function",
                    title=f"RPC function '{rpc.name}' callable without authentication",
                    description=(
                        f"The RPC function '{rpc.name}' can be invoked with the anonymous key "
                        "without any authenticated session. Depending on what the function does, "
                        "this may expose sensitive logic or data."
                    ),
                    affected_resource=f"RPC Function: {rpc.name}",
                    recommendation=(
                        f"Add an authentication check inside '{rpc.name}' or restrict it via a "
                        "Supabase policy. Consider using: IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Unauthorized'; END IF;"
                    ),
                    evidence={
                        "function": rpc.name,
                        "response_status": rpc.response_status,
                        "parameters": list(rpc.parameters.keys()),
                    },
                )
            )
    return findings


def check_edge_function_auth(
    client: SupabaseClient,
    edge_functions: list[str],
) -> tuple[list[EdgeFunction], list[Finding]]:
    results = []
    findings = []

    for name in edge_functions:
        resp = client.call_edge_function(name, payload={}, include_auth=False)
        status = resp.status_code
        requires_jwt = status == 401
        fn = EdgeFunction(
            name=name,
            url=f"https://{client.creds.project_ref}.functions.supabase.co/{name}",
            requires_jwt=requires_jwt,
            status_without_auth=status,
        )
        results.append(fn)

        if status in (200, 404, 500):
            findings.append(
                Finding(
                    severity=Severity.high,
                    type="edge_function_no_auth",
                    title=f"Edge function '{name}' does not require authentication",
                    description=(
                        f"The edge function '{name}' responded with HTTP {status} when called without "
                        "an Authorization header, indicating it does not enforce JWT authentication."
                    ),
                    affected_resource=f"Edge Function: {name}",
                    recommendation=(
                        f"Add JWT verification to '{name}' using the Authorization header. "
                        "Check the request for a valid Bearer token before processing."
                    ),
                    evidence={
                        "function": name,
                        "url": fn.url,
                        "status_without_auth": status,
                    },
                )
            )
    return results, findings


def run_all_passive_checks(
    client: SupabaseClient,
    tables: list[TableInfo],
    rpcs: list[RPCFunction],
    buckets: list[StorageBucket],
    edge_function_names: list[str],
) -> tuple[list[EdgeFunction], list[Finding]]:
    findings: list[Finding] = []
    findings.extend(check_rls(tables))
    findings.extend(check_public_buckets(buckets))
    findings.extend(check_public_rpcs(rpcs))
    edge_functions, edge_findings = check_edge_function_auth(client, edge_function_names)
    findings.extend(edge_findings)
    return edge_functions, findings
