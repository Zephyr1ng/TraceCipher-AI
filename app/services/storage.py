from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from app.config import APP_TIMEZONE, LLM_HISTORY_LIMIT
from app.models import AnalysisReport, AnalysisRequest, LLMConfig, LLMHistoryEntry, SourceArtifact, SourceSummary, TaskRecord


def create_run_dir(base_dir: Path) -> Path:
    run_id = uuid.uuid4().hex[:12]
    run_dir = base_dir / run_id
    (run_dir / "sources").mkdir(parents=True, exist_ok=True)
    (run_dir / "normalized").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    return run_dir


def parse_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def normalize_multiline_urls(value: str | None) -> list[str]:
    if not value:
        return []
    parts = re.split(r"[\s,]+", value.strip())
    return [part for part in parts if part]


def decode_bytes(raw: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def persist_source(
    run_dir: Path,
    *,
    name: str,
    content: str,
    origin: str,
    source_url: str | None = None,
    discovered_from: str | None = None,
    notes: list[str] | None = None,
) -> SourceArtifact:
    source_dir = run_dir / "sources"
    filename = _ensure_unique_filename(source_dir, sanitize_filename(name))
    path = source_dir / filename
    path.write_text(content, encoding="utf-8")
    return SourceArtifact(
        name=filename,
        origin=origin,
        source_url=source_url,
        saved_path=str(path),
        discovered_from=discovered_from,
        content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        content=content,
        notes=notes or [],
    )


def normalize_source_copy(run_dir: Path, source: SourceArtifact, normalized_content: str) -> str:
    normalized_dir = run_dir / "normalized"
    filename = _ensure_unique_filename(normalized_dir, sanitize_filename(source.name))
    path = normalized_dir / filename
    path.write_text(normalized_content, encoding="utf-8")
    return str(path)


def save_artifact_json(run_dir: Path, relative_path: str, payload: object) -> str:
    path = run_dir / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return relative_path


def save_artifact_text(run_dir: Path, relative_path: str, content: str) -> str:
    path = run_dir / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return relative_path


def list_artifact_paths(run_dir: Path, prefix: str | None = None) -> list[str]:
    artifacts_dir = run_dir / "artifacts"
    if not artifacts_dir.exists():
        return []
    files = []
    for target in sorted(artifacts_dir.rglob("*")):
        if not target.is_file():
            continue
        relative = target.relative_to(run_dir).as_posix()
        if prefix and not relative.startswith(prefix):
            continue
        files.append(relative)
    return files


def source_summary(source: SourceArtifact) -> SourceSummary:
    return SourceSummary(
        name=source.name,
        origin=source.origin,
        source_url=source.source_url,
        saved_path=source.saved_path,
        discovered_from=source.discovered_from,
        notes=source.notes,
    )


def load_report(run_dir: Path) -> AnalysisReport | None:
    report_path = run_dir / "report.json"
    if not report_path.exists():
        return None
    raw_text = report_path.read_text(encoding="utf-8")
    try:
        return AnalysisReport.model_validate_json(raw_text)
    except Exception:
        try:
            payload = json.loads(raw_text)
        except Exception:
            return None
        migrated = _migrate_report_payload(payload)
        try:
            return AnalysisReport.model_validate(migrated)
        except Exception:
            return None


def save_analysis_request(run_dir: Path, analysis_request: AnalysisRequest) -> None:
    request_path = run_dir / "request.json"
    request_path.write_text(analysis_request.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")


def load_analysis_request(run_dir: Path) -> AnalysisRequest | None:
    request_path = run_dir / "request.json"
    if request_path.exists():
        try:
            return AnalysisRequest.model_validate_json(request_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    report = load_report(run_dir)
    if report is None:
        return None
    return AnalysisRequest(
        parameter_name=report.parameter_name,
        parameter_type=report.parameter_type,
        parameter_location=report.parameter_location,
        parameter_hint=report.parameter_hint,
        api_context=report.api_context,
        webpage_url=report.webpage_url,
        external_js_urls=report.external_js_urls,
        llm=LLMConfig(
            provider_name=report.llm.provider,
            model_name=report.llm.model,
            max_concurrency=None,
            system_prompt=report.llm.system_prompt,
            operator_prompt=report.llm.operator_prompt,
        ),
    )


def load_saved_llm_config(path: Path) -> LLMConfig:
    if not path.exists():
        return LLMConfig()
    try:
        return LLMConfig.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception:
        return LLMConfig()


def save_saved_llm_config(path: Path, llm_config: LLMConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        llm_config.model_dump_json(indent=2, exclude_none=True),
        encoding="utf-8",
    )


def merge_llm_config(current: LLMConfig, saved: LLMConfig) -> LLMConfig:
    return LLMConfig(
        profile_name=current.profile_name or saved.profile_name,
        provider_name=current.provider_name or saved.provider_name,
        base_url=current.base_url or saved.base_url,
        model_name=current.model_name or saved.model_name,
        api_key=current.api_key or saved.api_key,
        analysis_mode=current.analysis_mode or saved.analysis_mode,
        self_review_enabled=(
            current.self_review_enabled
            if current.self_review_enabled is not None
            else saved.self_review_enabled
        ),
        glm_thinking_enabled=(
            current.glm_thinking_enabled
            if current.glm_thinking_enabled is not None
            else saved.glm_thinking_enabled
        ),
        max_concurrency=current.max_concurrency or saved.max_concurrency,
        max_tokens=current.max_tokens or saved.max_tokens,
        system_prompt=current.system_prompt or saved.system_prompt,
        operator_prompt=current.operator_prompt or saved.operator_prompt,
    )


def _migrate_report_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        return payload
    generated_artifact = payload.get("generated_artifact")
    if isinstance(generated_artifact, dict) and generated_artifact.get("script_type") == "python-node-bridge":
        generated_artifact["script_type"] = "report-only"
        notes = generated_artifact.get("notes")
        if not isinstance(notes, list):
            notes = []
        notes.append("历史结果曾使用 Python + Node bridge，当前版本已自动迁移为仅生成报告。")
        generated_artifact["notes"] = notes
    return payload


def load_llm_history(path: Path) -> list[LLMHistoryEntry]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    raw_entries = payload if isinstance(payload, list) else payload.get("entries", [])
    entries: list[LLMHistoryEntry] = []
    for item in raw_entries:
        try:
            entries.append(LLMHistoryEntry.model_validate(item))
        except Exception:
            continue
    entries.sort(key=lambda entry: display_datetime(entry.last_used_at), reverse=True)
    return entries


def save_llm_history(path: Path, entries: list[LLMHistoryEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    trimmed = sorted(entries, key=lambda entry: display_datetime(entry.last_used_at), reverse=True)[:LLM_HISTORY_LIMIT]
    path.write_text(
        json.dumps([entry.model_dump(mode="json", exclude_none=True) for entry in trimmed], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_llm_history_entry(path: Path, entry_id: str) -> LLMHistoryEntry | None:
    for entry in load_llm_history(path):
        if entry.entry_id == entry_id:
            return entry
    return None


def delete_llm_history_entry(path: Path, entry_id: str) -> bool:
    entries = load_llm_history(path)
    kept = [entry for entry in entries if entry.entry_id != entry_id]
    if len(kept) == len(entries):
        return False
    save_llm_history(path, kept)
    return True


def upsert_llm_history_entry(
    path: Path,
    *,
    llm_config: LLMConfig,
    mark_used: bool = True,
) -> LLMHistoryEntry:
    entries = load_llm_history(path)
    now = now_local()
    fingerprint = _llm_config_fingerprint(llm_config)

    for entry in entries:
        if _llm_config_fingerprint(entry.llm) != fingerprint:
            continue
        entry.llm = llm_config
        entry.profile_name = llm_config.profile_name or entry.profile_name or _default_llm_profile_name(llm_config)
        entry.updated_at = now
        if mark_used:
            entry.last_used_at = now
        save_llm_history(path, entries)
        return entry

    entry = LLMHistoryEntry(
        entry_id=uuid.uuid4().hex[:12],
        profile_name=llm_config.profile_name or _default_llm_profile_name(llm_config),
        llm=llm_config,
        created_at=now,
        updated_at=now,
        last_used_at=now if mark_used else now,
    )
    entries.insert(0, entry)
    save_llm_history(path, entries)
    return entry


def save_task(run_dir: Path, task: TaskRecord) -> None:
    task_path = run_dir / "task.json"
    task_path.write_text(task.model_dump_json(indent=2), encoding="utf-8")


def load_task(run_dir: Path) -> TaskRecord | None:
    task_path = run_dir / "task.json"
    if not task_path.exists():
        return None
    return TaskRecord.model_validate_json(task_path.read_text(encoding="utf-8"))


def list_tasks(base_dir: Path) -> list[TaskRecord]:
    tasks: list[TaskRecord] = []
    if not base_dir.exists():
        return tasks
    for run_dir in base_dir.iterdir():
        if not run_dir.is_dir():
            continue
        task = load_task(run_dir)
        if task is not None:
            tasks.append(task)
    tasks.sort(key=lambda item: display_datetime(item.updated_at), reverse=True)
    return tasks


def build_task(run_dir: Path, parameter_name: str, *, status: str, progress: int, current_step: str) -> TaskRecord:
    now = now_local()
    return TaskRecord(
        run_id=run_dir.name,
        parameter_name=parameter_name,
        created_at=now,
        updated_at=now,
        status=status,
        progress=progress,
        current_step=current_step,
        result_ready=status == "completed",
    )


def update_task(
    run_dir: Path,
    *,
    status: str | None = None,
    progress: int | None = None,
    current_step: str | None = None,
    error_message: str | None = None,
    error_raw_message: str | None = None,
    result_ready: bool | None = None,
) -> TaskRecord:
    task = load_task(run_dir)
    if task is None:
        raise FileNotFoundError(f"未找到任务：{run_dir}")
    if status is not None:
        task.status = status
    if progress is not None:
        task.progress = max(0, min(progress, 100))
    if current_step is not None:
        task.current_step = current_step
    if error_message is not None:
        task.error_message = error_message
    if error_raw_message is not None:
        task.error_raw_message = error_raw_message
    if result_ready is not None:
        task.result_ready = result_ready
    task.updated_at = now_local()
    save_task(run_dir, task)
    return task


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def delete_run_dir(run_dir: Path) -> None:
    if run_dir.exists():
        shutil.rmtree(run_dir)


def now_local() -> datetime:
    return datetime.now(APP_TIMEZONE)


def display_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(APP_TIMEZONE)


def format_datetime(value: datetime) -> str:
    return display_datetime(value).strftime("%Y-%m-%d %H:%M:%S")


def sanitize_filename(name: str) -> str:
    base = Path(name).name or "source.js"
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    return cleaned or "source.js"


def mask_api_key(value: str | None) -> str:
    if not value:
        return ""
    compact = value.strip()
    if len(compact) <= 10:
        return "*" * len(compact)
    return f"{compact[:4]}***{compact[-4:]}"


def _llm_config_fingerprint(llm_config: LLMConfig) -> str:
    payload = {
        "provider_name": llm_config.provider_name or "",
        "base_url": llm_config.base_url or "",
        "model_name": llm_config.model_name or "",
        "api_key": llm_config.api_key or "",
        "analysis_mode": llm_config.analysis_mode or "",
        "self_review_enabled": llm_config.self_review_enabled,
        "glm_thinking_enabled": llm_config.glm_thinking_enabled,
        "max_concurrency": llm_config.max_concurrency or "",
        "max_tokens": llm_config.max_tokens or "",
        "system_prompt": llm_config.system_prompt or "",
        "operator_prompt": llm_config.operator_prompt or "",
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _default_llm_profile_name(llm_config: LLMConfig) -> str:
    model_name = llm_config.model_name or "deepseek"
    return f"{model_name} · {format_datetime(now_local())}"


def _ensure_unique_filename(directory: Path, filename: str) -> str:
    candidate = filename
    stem = Path(filename).stem or "file"
    suffix = Path(filename).suffix
    index = 1
    while (directory / candidate).exists():
        candidate = f"{stem}_{index}{suffix}"
        index += 1
    return candidate
