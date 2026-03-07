from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class WriteResult(Enum):
    allowed = "allowed"
    denied = "denied"
    possible = "possible"


@dataclass
class Credentials:
    project_ref: str
    anon_key: str
    user_token: Optional[str] = None
    source: Optional[str] = None

    @property
    def base_url(self) -> str:
        return f"https://{self.project_ref}.supabase.co"


@dataclass
class ColumnInfo:
    name: str
    type: str
    nullable: bool
    is_primary: bool


@dataclass
class TableInfo:
    name: str
    columns: list[ColumnInfo] = field(default_factory=list)
    accessible: bool = False
    sample_data: list[dict] = field(default_factory=list)


@dataclass
class RPCFunction:
    name: str
    parameters: dict = field(default_factory=dict)
    accessible: bool = False
    response_status: Optional[int] = None


@dataclass
class StorageBucket:
    name: str
    public: bool = False
    accessible: bool = False
    file_count: int = 0


@dataclass
class Finding:
    severity: Severity
    type: str
    title: str
    description: str
    affected_resource: str
    recommendation: str
    evidence: dict = field(default_factory=dict)


@dataclass
class WriteTestResult:
    table: str
    insert_result: WriteResult = WriteResult.denied
    update_result: WriteResult = WriteResult.denied
    delete_result: WriteResult = WriteResult.denied
    inserted_id: Optional[Any] = None


@dataclass
class EdgeFunction:
    name: str
    url: str
    requires_jwt: bool = True
    status_without_auth: Optional[int] = None


@dataclass
class AuditReport:
    target: str
    timestamp: str
    findings: list[Finding] = field(default_factory=list)
    tables: list[TableInfo] = field(default_factory=list)
    rpc_functions: list[RPCFunction] = field(default_factory=list)
    buckets: list[StorageBucket] = field(default_factory=list)
    edge_functions: list[EdgeFunction] = field(default_factory=list)
    write_results: list[WriteTestResult] = field(default_factory=list)
