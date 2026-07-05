from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class AssetKind(str, Enum):
    html = "html"
    script = "script"
    inline_script = "inline_script"
    source_map = "source_map"
    unknown = "unknown"


class Location(BaseModel):
    file: str | None = None
    url: str | None = None
    line: int | None = None
    column: int | None = None
    generated_file: str | None = None
    generated_line: int | None = None
    generated_column: int | None = None


class JSAsset(BaseModel):
    asset_id: str
    kind: AssetKind = AssetKind.script
    url: str | None = None
    path: str | None = None
    asset_role: str = "unknown"
    fetch_priority: int = 0
    hash: str
    size: int
    raw_code: str = ""
    normalized_code: str = ""
    source_map_url: str | None = None
    first_seen_page: str | None = None
    third_party: bool = False
    minified: bool = False


class ParamLocation(str, Enum):
    path = "path"
    query = "query"
    body = "body"
    header = "header"
    cookie = "cookie"
    unknown = "unknown"


class APIParam(BaseModel):
    name: str
    location: ParamLocation = ParamLocation.unknown
    source_expr: str | None = None
    type_hint: str | None = None
    user_controllable: bool | None = None
    risk_tags: list[str] = Field(default_factory=list)
    flow: list[str] = Field(default_factory=list)
    transforms: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    type: str
    location: Location = Field(default_factory=Location)
    code: str | None = None
    confidence: float = 0.5
    notes: list[str] = Field(default_factory=list)


class APIAsset(BaseModel):
    id: str
    method: str = "GET"
    url: str
    url_template: str
    client: str = "unknown"
    wrapper: str | None = None
    body_raw: str | None = None
    possible_body_fields: list[str] = Field(default_factory=list)
    params: list[APIParam] = Field(default_factory=list)
    headers: list[str] = Field(default_factory=list)
    transforms: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    risk_tags: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    priority: int = 0
    auth_required: bool | None = None
    cluster: str | None = None


class WrapperCandidate(BaseModel):
    wrapper_id: str
    name: str
    defined_in: str | None = None
    backend: str | None = None
    params: list[str] = Field(default_factory=list)
    adds_headers: list[str] = Field(default_factory=list)
    has_interceptor: bool = False
    has_sign_logic: bool = False
    has_encrypt_logic: bool = False
    confidence: float = 0.5
    evidence: list[Evidence] = Field(default_factory=list)


class CallGraphEdge(BaseModel):
    caller: str
    callee: str
    location: Location = Field(default_factory=Location)


class APISemanticCluster(BaseModel):
    id: str
    label: str
    api_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    priority: int = 0


class AssetAnalysisTrace(BaseModel):
    asset_ref: str
    priority: int = 0
    strategy: str = "full"
    quick_hits: list[str] = Field(default_factory=list)
    candidate_endpoints: list[str] = Field(default_factory=list)
    extracted_api_count: int = 0
    skipped_reason: str | None = None


class ExposureFinding(BaseModel):
    id: str
    kind: str
    name: str
    value: str
    source: str | None = None
    severity: int = 0
    confidence: float = 0.5
    location: Location = Field(default_factory=Location)


class FingerprintFinding(BaseModel):
    category: str
    name: str
    source: str | None = None
    confidence: float = 0.5
    evidence: str | None = None


class StaticAnalysisReport(BaseModel):
    target: str
    assets: list[JSAsset] = Field(default_factory=list)
    wrappers: list[WrapperCandidate] = Field(default_factory=list)
    apis: list[APIAsset] = Field(default_factory=list)
    call_graph: list[CallGraphEdge] = Field(default_factory=list)
    clusters: list[APISemanticCluster] = Field(default_factory=list)
    asset_traces: list[AssetAnalysisTrace] = Field(default_factory=list)
    exposures: list[ExposureFinding] = Field(default_factory=list)
    fingerprints: list[FingerprintFinding] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
