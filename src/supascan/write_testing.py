from __future__ import annotations
import uuid
from typing import Any

from .client import SupabaseClient
from .models import Finding, Severity, TableInfo, WriteResult, WriteTestResult


def _find_primary_key(table: TableInfo) -> str:
    for col in table.columns:
        if col.is_primary:
            return col.name
    return "id"


def _generate_test_payload(table: TableInfo) -> dict:
    if not table.sample_data:
        return {"_supascan_test": True}

    row = dict(table.sample_data[0])
    pk = _find_primary_key(table)

    for col in table.columns:
        if col.name not in row:
            continue
        val = row[col.name]
        if col.is_primary:
            # Generate new UUID for uuid PKs; skip int PKs (auto-increment)
            if col.type in ("string", "uuid") and isinstance(val, str):
                row[col.name] = str(uuid.uuid4())
            else:
                del row[col.name]
        elif isinstance(val, str):
            row[col.name] = val + "_supascan_test"
        elif isinstance(val, int):
            row[col.name] = val + 9999
        # Leave other types as-is

    return row


def _status_to_result(status: int) -> WriteResult:
    if status in (200, 201):
        return WriteResult.allowed
    if status in (401, 403):
        return WriteResult.denied
    return WriteResult.possible


def test_insert(client: SupabaseClient, table: TableInfo) -> tuple[WriteResult, Any]:
    payload = _generate_test_payload(table)
    resp = client.insert_row(table.name, payload)
    result = _status_to_result(resp.status_code)
    inserted_id = None
    if result == WriteResult.allowed:
        try:
            data = resp.json()
            if isinstance(data, list) and data:
                pk = _find_primary_key(table)
                inserted_id = data[0].get(pk)
        except Exception:
            pass
    return result, inserted_id


def test_update(
    client: SupabaseClient,
    table: TableInfo,
    write_result: WriteTestResult,
) -> WriteResult:
    pk = _find_primary_key(table)
    filter_val = write_result.inserted_id

    if filter_val is None and table.sample_data:
        filter_val = table.sample_data[0].get(pk)

    if filter_val is None:
        return WriteResult.denied

    # Find a non-PK string field to patch
    patch: dict = {}
    for col in table.columns:
        if col.is_primary:
            continue
        if table.sample_data:
            val = table.sample_data[0].get(col.name)
            if isinstance(val, str):
                patch[col.name] = val + "_supascan_patched"
                break
            elif isinstance(val, int):
                patch[col.name] = val + 1
                break

    if not patch:
        patch = {"_supascan_patched": True}

    resp = client.update_row(table.name, pk, filter_val, patch)
    return _status_to_result(resp.status_code)


def test_delete(
    client: SupabaseClient,
    table: TableInfo,
    write_result: WriteTestResult,
) -> WriteResult:
    pk = _find_primary_key(table)
    filter_val = write_result.inserted_id

    if filter_val is None:
        return WriteResult.denied

    try:
        resp = client.delete_row(table.name, pk, filter_val)
        return _status_to_result(resp.status_code)
    finally:
        # Always attempt cleanup even if delete fails
        pass


def run_write_tests(
    client: SupabaseClient,
    tables: list[TableInfo],
) -> tuple[list[WriteTestResult], list[Finding]]:
    results: list[WriteTestResult] = []
    findings: list[Finding] = []

    for table in tables:
        wtr = WriteTestResult(table=table.name)

        insert_result, inserted_id = test_insert(client, table)
        wtr.insert_result = insert_result
        wtr.inserted_id = inserted_id

        if insert_result == WriteResult.allowed:
            findings.append(
                Finding(
                    severity=Severity.critical,
                    type="unauthenticated_write",
                    title=f"Table '{table.name}' allows anonymous INSERT",
                    description=(
                        f"An unauthenticated request successfully inserted a row into '{table.name}'. "
                        "Row Level Security is either disabled or has an overly permissive INSERT policy."
                    ),
                    affected_resource=f"Table: {table.name}",
                    recommendation=(
                        f"Enable RLS and restrict INSERT to authenticated users only. "
                        f"Use: CREATE POLICY \"deny_anon_insert\" ON {table.name} FOR INSERT TO authenticated WITH CHECK (true);"
                    ),
                    evidence={"table": table.name, "operation": "INSERT", "inserted_id": str(inserted_id)},
                )
            )
            wtr.update_result = test_update(client, table, wtr)
            if wtr.update_result == WriteResult.allowed:
                findings.append(
                    Finding(
                        severity=Severity.critical,
                        type="unauthenticated_write",
                        title=f"Table '{table.name}' allows anonymous UPDATE",
                        description=(
                            f"An unauthenticated request successfully updated a row in '{table.name}'. "
                            "Row Level Security is either disabled or has an overly permissive UPDATE policy."
                        ),
                        affected_resource=f"Table: {table.name}",
                        recommendation=(
                            f"Restrict UPDATE to authenticated users. "
                            f"Use: CREATE POLICY \"deny_anon_update\" ON {table.name} FOR UPDATE TO authenticated USING (true);"
                        ),
                        evidence={"table": table.name, "operation": "UPDATE"},
                    )
                )
            wtr.delete_result = test_delete(client, table, wtr)
            if wtr.delete_result == WriteResult.allowed:
                findings.append(
                    Finding(
                        severity=Severity.critical,
                        type="unauthenticated_write",
                        title=f"Table '{table.name}' allows anonymous DELETE",
                        description=(
                            f"An unauthenticated request successfully deleted a row from '{table.name}'. "
                            "Row Level Security is either disabled or has an overly permissive DELETE policy."
                        ),
                        affected_resource=f"Table: {table.name}",
                        recommendation=(
                            f"Restrict DELETE to authenticated users. "
                            f"Use: CREATE POLICY \"deny_anon_delete\" ON {table.name} FOR DELETE TO authenticated USING (true);"
                        ),
                        evidence={"table": table.name, "operation": "DELETE"},
                    )
                )
        else:
            # Still attempt cleanup if we somehow inserted (possible result)
            if insert_result == WriteResult.possible and inserted_id:
                test_delete(client, table, wtr)

        results.append(wtr)

    return results, findings
