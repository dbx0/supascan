from __future__ import annotations
from typing import Optional

from .client import SupabaseClient
from .models import ColumnInfo, RPCFunction, StorageBucket, TableInfo


def parse_openapi_columns(spec: dict, table_name: str) -> list[ColumnInfo]:
    columns = []
    definitions = spec.get("definitions", {})
    table_def = definitions.get(table_name, {})
    properties = table_def.get("properties", {})
    required = set(table_def.get("required", []))
    pk_fields = set()

    # PostgREST marks primary keys with x-constraint or description
    for col_name, col_def in properties.items():
        desc = col_def.get("description", "")
        if "Primary Key" in desc or col_def.get("x-is-pk"):
            pk_fields.add(col_name)

    for col_name, col_def in properties.items():
        col_type = col_def.get("type", col_def.get("format", "unknown"))
        if isinstance(col_type, list):
            col_type = col_type[0]
        columns.append(
            ColumnInfo(
                name=col_name,
                type=str(col_type),
                nullable=col_name not in required,
                is_primary=col_name in pk_fields or col_name == "id",
            )
        )
    return columns


def enumerate_tables(client: SupabaseClient) -> list[TableInfo]:
    resp = client.get_openapi_spec()
    if resp.status_code != 200:
        return []

    try:
        spec = resp.json()
    except Exception:
        return []

    tables = []
    paths = spec.get("paths", {})
    for path, path_def in paths.items():
        # Skip RPC paths
        if path.startswith("/rpc/"):
            continue
        table_name = path.lstrip("/")
        if not table_name:
            continue

        columns = parse_openapi_columns(spec, table_name)
        table = TableInfo(name=table_name, columns=columns)

        # Try to fetch sample data
        data_resp = client.query_table(table_name, limit=5)
        if data_resp.status_code == 200:
            table.accessible = True
            try:
                table.sample_data = data_resp.json()
            except Exception:
                table.sample_data = []
        else:
            table.accessible = False

        tables.append(table)
    return tables


def enumerate_rpc_functions(client: SupabaseClient) -> list[RPCFunction]:
    try:
        resp = client.get_openapi_spec()
    except Exception:
        return []
    if resp.status_code != 200:
        return []

    try:
        spec = resp.json()
    except Exception:
        return []

    rpcs = []
    paths = spec.get("paths", {})
    for path, path_def in paths.items():
        if not path.startswith("/rpc/"):
            continue
        name = path[len("/rpc/"):]
        if not name:
            continue

        # Extract parameters from POST body schema
        parameters = {}
        post_def = path_def.get("post", {})
        params_schema = post_def.get("parameters", [])
        for param in params_schema:
            if param.get("in") == "body":
                schema = param.get("schema", {})
                parameters = schema.get("properties", {})
                break

        rpc_resp = client.call_rpc(name, {})
        accessible = rpc_resp.status_code not in (401, 403)

        rpcs.append(
            RPCFunction(
                name=name,
                parameters=parameters,
                accessible=accessible,
                response_status=rpc_resp.status_code,
            )
        )
    return rpcs


def enumerate_buckets(client: SupabaseClient) -> list[StorageBucket]:
    try:
        resp = client.list_buckets()
    except Exception:
        return []
    if resp.status_code != 200:
        return []

    try:
        raw_buckets = resp.json()
    except Exception:
        return []

    if not isinstance(raw_buckets, list):
        return []

    buckets = []
    for b in raw_buckets:
        name = b.get("name", b.get("id", ""))
        is_public = b.get("public", False)

        obj_resp = client.list_bucket_objects(name)
        accessible = obj_resp.status_code == 200
        file_count = 0
        if accessible:
            try:
                objects = obj_resp.json()
                file_count = len(objects) if isinstance(objects, list) else 0
            except Exception:
                pass

        buckets.append(
            StorageBucket(
                name=name,
                public=is_public,
                accessible=accessible,
                file_count=file_count,
            )
        )
    return buckets
