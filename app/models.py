from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class SourceArtifact(BaseModel):
    name: str
    origin: Literal["upload", "zip", "webpage", "external_url"]
    source_url: str | None = None
    saved_path: str | None = None
    discovered_from: str | None = None
    content_hash: str
    content: str
    notes: list[str] = Field(default_factory=list)


class SourceSummary(BaseModel):
    name: str
    origin: str
    source_url: str | None = None
    saved_path: str | None = None
    discovered_from: str | None = None
    notes: list[str] = Field(default_factory=list)


class CandidateTrace(BaseModel):
    file_name: str
    source_url: str | None = None
    line_number: int
    function_name: str | None = None
    function_line: int | None = None
    score: float
    markers: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    request_clues: list[str] = Field(default_factory=list)
    snippet: str
    function_excerpt: str | None = None
    call_chain: list[str] = Field(default_factory=list)
    summary: str


class ValidationResult(BaseModel):
    status: Literal["not_run", "passed", "partial", "failed"]
    details: list[str] = Field(default_factory=list)


class GeneratedArtifact(BaseModel):
    script_type: Literal["pure-python", "report-only"]
    files: list[str] = Field(default_factory=list)
    runtime: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class LLMInsight(BaseModel):
    used: bool = False
    provider: str | None = None
    model: str | None = None
    system_prompt: str | None = None
    operator_prompt: str | None = None
    summary: str | None = None
    reversibility: str | None = None
    confidence: float | None = None
    flow_steps: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    inferred_operations: list[str] = Field(default_factory=list)
    function_chain: list[str] = Field(default_factory=list)
    preferred_script_type: str | None = None
    selected_candidates: list[str] = Field(default_factory=list)
    observed_facts: list[str] = Field(default_factory=list)
    reasoning_notes: list[str] = Field(default_factory=list)
    key_material: dict[str, str] = Field(default_factory=dict)
    raw_excerpt: str | None = None


class AnalysisReport(BaseModel):
    run_id: str
    created_at: datetime
    parameter_name: str
    parameter_type: str
    parameter_location: str
    parameter_hint: str | None = None
    api_context: str | None = None
    webpage_url: str | None = None
    external_js_urls: list[str] = Field(default_factory=list)
    summary: str
    reversibility: str
    confidence: float
    sources: list[SourceSummary]
    flow_steps: list[str] = Field(default_factory=list)
    candidates: list[CandidateTrace] = Field(default_factory=list)
    generated_artifact: GeneratedArtifact
    validation: ValidationResult
    llm: LLMInsight = Field(default_factory=LLMInsight)
    warnings: list[str] = Field(default_factory=list)


class AnalysisSessionSnippet(BaseModel):
    label: str
    file_name: str | None = None
    function_name: str | None = None
    line_hint: int | None = None
    content: str


class AnalysisSessionMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str
    created_at: datetime


class AnalysisSession(BaseModel):
    run_id: str
    created_at: datetime
    updated_at: datetime
    parameter_name: str
    summary: str
    reversibility: str
    operation_chain: list[str] = Field(default_factory=list)
    function_chain: list[str] = Field(default_factory=list)
    observed_facts: list[str] = Field(default_factory=list)
    key_material: dict[str, str] = Field(default_factory=dict)
    snippets: list[AnalysisSessionSnippet] = Field(default_factory=list)
    messages: list[AnalysisSessionMessage] = Field(default_factory=list)


class TaskRecord(BaseModel):
    run_id: str
    parameter_name: str
    created_at: datetime
    updated_at: datetime
    status: Literal["collecting", "queued", "running", "paused", "completed", "failed"]
    progress: int = 0
    current_step: str = ""
    error_message: str | None = None
    error_raw_message: str | None = None
    result_ready: bool = False


class LLMConfig(BaseModel):
    profile_name: str | None = None
    provider_name: str | None = None
    base_url: str | None = None
    model_name: str | None = None
    api_key: str | None = None
    analysis_mode: str | None = None
    self_review_enabled: bool | None = None
    glm_thinking_enabled: bool | None = None
    max_concurrency: int | None = None
    max_tokens: int | None = None
    system_prompt: str | None = None
    operator_prompt: str | None = None


class LLMHistoryEntry(BaseModel):
    entry_id: str
    profile_name: str
    llm: LLMConfig
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime


class AnalysisRequest(BaseModel):
    parameter_name: str
    parameter_type: str = "unknown"
    parameter_location: str = "unknown"
    parameter_hint: str | None = None
    api_context: str | None = None
    webpage_url: str | None = None
    external_js_urls: list[str] = Field(default_factory=list)
    validation_plaintext: str | None = None
    validation_ciphertext: str | None = None
    llm: LLMConfig = Field(default_factory=LLMConfig)
