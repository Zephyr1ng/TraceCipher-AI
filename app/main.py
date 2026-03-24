from __future__ import annotations

import json
import subprocess
import sys

from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import (
    DEEPSEEK_BASE_URL,
    DEEPSEEK_DEFAULT_MODEL,
    DEEPSEEK_REASONER_DEFAULT_MAX_TOKENS,
    GLM_BASE_URL,
    GLM_DEFAULT_MAX_TOKENS,
    GLM_DEFAULT_MODEL,
    LLM_DEFAULT_MAX_TOKENS,
    LLM_HISTORY_PATH,
    LLM_MAX_CONCURRENT_REQUESTS,
    LLM_MAX_CONCURRENT_REQUESTS_LIMIT,
    LLM_MAX_TOKENS_LIMIT,
    LLM_MIN_MAX_TOKENS,
    LLM_SETTINGS_PATH,
    RUNS_DIR,
    STATIC_DIR,
    TEMPLATES_DIR,
)
from app.models import AnalysisRequest, AnalysisReport, LLMConfig, TaskRecord
from app.services.ingestion import collect_sources, reuse_sources_from_run
from app.services.llm import (
    DEFAULT_OPERATOR_PROMPT,
    DEFAULT_SYSTEM_PROMPT,
    LLMAnalysisError,
    answer_followup_with_llm,
    validate_llm_config,
)
from app.services.session_manager import append_session_exchange, build_followup_payload, get_or_create_session
from app.services.storage import (
    build_task,
    create_run_dir,
    delete_run_dir,
    display_datetime,
    delete_llm_history_entry,
    format_datetime,
    list_artifact_paths,
    load_llm_history,
    load_llm_history_entry,
    list_tasks,
    load_analysis_request,
    load_report,
    load_saved_llm_config,
    load_task,
    mask_api_key,
    merge_llm_config,
    normalize_multiline_urls,
    parse_optional_text,
    save_analysis_request,
    save_task,
    save_saved_llm_config,
    upsert_llm_history_entry,
    update_task,
)
from app.services.task_manager import launch_analysis_task, pause_analysis_task


app = FastAPI(
    title="TraceCipher AI",
    description="面向授权安全测试的前端参数加密分析工具。",
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, draft: str | None = None) -> HTMLResponse:
    saved_llm = _normalize_provider_config(load_saved_llm_config(LLM_SETTINGS_PATH))
    draft_request = None
    draft_task = None
    active_llm = saved_llm
    defaults = {
        "draft_run_id": "",
        "parameter_name": "",
        "parameter_type": "unknown",
        "parameter_location": "unknown",
        "parameter_hint": "",
        "api_context": "",
        "webpage_url": "",
        "external_js_urls": "",
        "validation_plaintext": "",
        "validation_ciphertext": "",
    }
    draft_context = None
    if draft:
        draft_run_dir = RUNS_DIR / draft
        draft_task = load_task(draft_run_dir)
        draft_request = load_analysis_request(draft_run_dir)
        if draft_task is not None and draft_request is not None:
            defaults.update(
                {
                    "draft_run_id": draft,
                    "parameter_name": draft_request.parameter_name,
                    "parameter_type": draft_request.parameter_type,
                    "parameter_location": draft_request.parameter_location,
                    "parameter_hint": draft_request.parameter_hint or "",
                    "api_context": draft_request.api_context or "",
                    "webpage_url": draft_request.webpage_url or "",
                    "external_js_urls": "\n".join(draft_request.external_js_urls),
                    "validation_plaintext": draft_request.validation_plaintext or "",
                    "validation_ciphertext": draft_request.validation_ciphertext or "",
                }
            )
            active_llm = _normalize_provider_config(merge_llm_config(draft_request.llm, saved_llm))
            draft_context = {
                "run_id": draft_task.run_id,
                "parameter_name": draft_task.parameter_name,
                "can_reuse_sources": not draft_request.webpage_url and not draft_request.external_js_urls,
            }
    llm_history = [_llm_history_view(entry, active_llm) for entry in _load_supported_history()]
    recent_tasks = [_task_view(task) for task in list_tasks(RUNS_DIR)[:8]]
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "defaults": defaults,
            "provider_presets": _provider_presets(),
            "saved_llm": _saved_llm_view(active_llm),
            "llm_history": llm_history,
            "llm_history_map": {item["entry_id"]: item["config_payload"] for item in llm_history},
            "draft_context": draft_context,
            "recent_tasks": recent_tasks,
        },
    )


@app.post("/analyze")
async def analyze(
    request: Request,
    draft_run_id: str = Form(""),
    parameter_name: str = Form(...),
    parameter_type: str = Form("unknown"),
    parameter_location: str = Form("unknown"),
    parameter_hint: str = Form(""),
    api_context: str = Form(""),
    webpage_url: str = Form(""),
    external_js_urls: str = Form(""),
    validation_plaintext: str = Form(""),
    validation_ciphertext: str = Form(""),
    provider_name: str = Form("deepseek"),
    llm_profile_name: str = Form(""),
    llm_analysis_mode: str = Form("reasoner"),
    llm_base_url: str = Form(""),
    llm_model_name: str = Form(""),
    llm_api_key: str = Form(""),
    llm_self_review_mode: str = Form("enabled"),
    llm_glm_thinking_mode: str = Form("enabled"),
    llm_max_concurrency: int = Form(LLM_MAX_CONCURRENT_REQUESTS),
    llm_max_tokens: int = Form(LLM_DEFAULT_MAX_TOKENS),
    llm_system_prompt: str = Form(""),
    llm_operator_prompt: str = Form(""),
    uploads: list[UploadFile] | None = File(None),
) -> RedirectResponse:
    saved_llm = _normalize_provider_config(load_saved_llm_config(LLM_SETTINGS_PATH))
    requested_llm = _normalize_provider_config(
        LLMConfig(
            profile_name=parse_optional_text(llm_profile_name),
            provider_name=parse_optional_text(provider_name) or "deepseek",
            base_url=parse_optional_text(llm_base_url),
            model_name=parse_optional_text(llm_model_name),
            api_key=parse_optional_text(llm_api_key),
            analysis_mode=parse_optional_text(llm_analysis_mode),
            self_review_enabled=_normalize_llm_self_review_mode(llm_self_review_mode),
            glm_thinking_enabled=_normalize_glm_thinking_mode(llm_glm_thinking_mode),
            max_concurrency=_normalize_llm_concurrency(llm_max_concurrency),
            max_tokens=_normalize_llm_max_tokens(llm_max_tokens),
            system_prompt=parse_optional_text(llm_system_prompt),
            operator_prompt=parse_optional_text(llm_operator_prompt),
        )
    )
    merged_llm = _normalize_provider_config(merge_llm_config(requested_llm, saved_llm))
    run_dir = create_run_dir(RUNS_DIR)
    analysis_request = AnalysisRequest(
        parameter_name=parameter_name.strip(),
        parameter_type=parameter_type.strip() or "unknown",
        parameter_location=parameter_location.strip() or "unknown",
        parameter_hint=parse_optional_text(parameter_hint),
        api_context=parse_optional_text(api_context),
        webpage_url=parse_optional_text(webpage_url),
        external_js_urls=normalize_multiline_urls(external_js_urls),
        validation_plaintext=parse_optional_text(validation_plaintext),
        validation_ciphertext=parse_optional_text(validation_ciphertext),
        llm=merged_llm,
    )
    draft_run_id = draft_run_id.strip()

    task = build_task(
        run_dir,
        analysis_request.parameter_name,
        status="collecting",
        progress=5,
        current_step="正在收集源码与外部脚本",
    )
    save_task(run_dir, task)
    save_analysis_request(run_dir, analysis_request)

    try:
        validate_llm_config(analysis_request.llm)
        save_saved_llm_config(LLM_SETTINGS_PATH, analysis_request.llm)
        upsert_llm_history_entry(LLM_HISTORY_PATH, llm_config=analysis_request.llm)
    except LLMAnalysisError as exc:
        update_task(
            run_dir,
            status="failed",
            progress=100,
            current_step="任务创建失败",
            error_message=exc.message,
            error_raw_message=exc.raw_message,
            result_ready=False,
        )
        return RedirectResponse(url=f"/tasks/{run_dir.name}", status_code=303)

    sources, ingestion_notes, ingestion_warnings = await collect_sources(
        run_dir=run_dir,
        webpage_url=analysis_request.webpage_url,
        external_js_urls=analysis_request.external_js_urls,
        uploads=uploads or [],
    )
    if not sources and draft_run_id:
        draft_sources, draft_notes, draft_warnings = reuse_sources_from_run(
            run_dir=run_dir,
            draft_run_dir=RUNS_DIR / draft_run_id,
        )
        sources = draft_sources
        ingestion_notes.extend(draft_notes)
        ingestion_warnings.extend(draft_warnings)
    if not sources:
        update_task(
            run_dir,
            status="failed",
            progress=100,
            current_step="源码收集失败",
            error_message="没有收集到可分析的 JS 文件，请上传源码或提供可访问的 URL。",
            result_ready=False,
        )
        return RedirectResponse(url=f"/tasks/{run_dir.name}", status_code=303)

    update_task(
        run_dir,
        status="queued",
        progress=20,
        current_step="源码收集完成，等待开始分析",
        result_ready=False,
    )
    launch_analysis_task(
        run_dir=run_dir,
        analysis_request=analysis_request,
        sources=sources,
        ingestion_notes=ingestion_notes,
        ingestion_warnings=ingestion_warnings,
    )
    return RedirectResponse(url=f"/tasks/{run_dir.name}", status_code=303)


@app.get("/tasks", response_class=HTMLResponse)
async def task_list(request: Request) -> HTMLResponse:
    tasks = [_task_view(task) for task in list_tasks(RUNS_DIR)]
    return templates.TemplateResponse(
        request=request,
        name="tasks.html",
        context={"tasks": tasks},
    )


@app.post("/settings/llm")
async def save_llm_settings(
    provider_name: str = Form("deepseek"),
    llm_profile_name: str = Form(""),
    llm_analysis_mode: str = Form("reasoner"),
    llm_base_url: str = Form(""),
    llm_model_name: str = Form(""),
    llm_api_key: str = Form(""),
    llm_self_review_mode: str = Form("enabled"),
    llm_glm_thinking_mode: str = Form("enabled"),
    llm_max_concurrency: int = Form(LLM_MAX_CONCURRENT_REQUESTS),
    llm_max_tokens: int = Form(LLM_DEFAULT_MAX_TOKENS),
    llm_system_prompt: str = Form(""),
    llm_operator_prompt: str = Form(""),
) -> dict[str, str]:
    llm_config = _normalize_provider_config(
        LLMConfig(
            profile_name=parse_optional_text(llm_profile_name),
            provider_name=parse_optional_text(provider_name) or "deepseek",
            base_url=parse_optional_text(llm_base_url),
            model_name=parse_optional_text(llm_model_name),
            api_key=parse_optional_text(llm_api_key),
            analysis_mode=parse_optional_text(llm_analysis_mode),
            self_review_enabled=_normalize_llm_self_review_mode(llm_self_review_mode),
            glm_thinking_enabled=_normalize_glm_thinking_mode(llm_glm_thinking_mode),
            max_concurrency=_normalize_llm_concurrency(llm_max_concurrency),
            max_tokens=_normalize_llm_max_tokens(llm_max_tokens),
            system_prompt=parse_optional_text(llm_system_prompt),
            operator_prompt=parse_optional_text(llm_operator_prompt),
        )
    )
    try:
        validate_llm_config(llm_config)
    except LLMAnalysisError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    save_saved_llm_config(LLM_SETTINGS_PATH, llm_config)
    history_entry = upsert_llm_history_entry(LLM_HISTORY_PATH, llm_config=llm_config)
    provider_label = "GLM" if (llm_config.provider_name or "").lower() == "glm" else "DeepSeek"
    return {"message": f"默认 {provider_label} 配置已保存，后续创建任务会自动复用。", "entry_id": history_entry.entry_id}


@app.post("/settings/llm/history/{entry_id}/activate")
async def activate_llm_history_entry(entry_id: str) -> dict[str, str]:
    entry = load_llm_history_entry(LLM_HISTORY_PATH, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="未找到对应的模型配置历史记录。")
    llm_config = _normalize_provider_config(entry.llm)
    save_saved_llm_config(LLM_SETTINGS_PATH, llm_config)
    upsert_llm_history_entry(LLM_HISTORY_PATH, llm_config=llm_config)
    provider_label = "GLM" if (llm_config.provider_name or "").lower() == "glm" else "DeepSeek"
    return {"message": f"已将选中的 {provider_label} 配置设为当前默认配置。"}


@app.post("/settings/llm/history/{entry_id}/delete")
async def remove_llm_history_entry(entry_id: str) -> dict[str, str]:
    deleted = delete_llm_history_entry(LLM_HISTORY_PATH, entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="未找到对应的模型配置历史记录。")
    return {"message": "模型配置历史已删除。"}


@app.get("/tasks/{run_id}", response_class=HTMLResponse)
async def task_detail(run_id: str, request: Request) -> HTMLResponse:
    run_dir = RUNS_DIR / run_id
    task = load_task(run_dir)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在。")
    if task.status == "completed":
        return RedirectResponse(url=f"/runs/{run_id}", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="task_detail.html",
        context={
            "task": _task_view(task, detail_mode=True),
            "llm_debug_files": _llm_debug_file_links(run_dir),
        },
    )


@app.post("/tasks/{run_id}/delete")
async def delete_task(run_id: str) -> RedirectResponse:
    run_dir = RUNS_DIR / run_id
    task = load_task(run_dir)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在。")
    if task.status in {"collecting", "queued", "running"}:
        raise HTTPException(status_code=400, detail="运行中的任务暂不支持删除。")
    delete_run_dir(run_dir)
    return RedirectResponse(url="/tasks", status_code=303)


@app.post("/tasks/{run_id}/pause")
async def pause_task(run_id: str) -> RedirectResponse:
    run_dir = RUNS_DIR / run_id
    task = load_task(run_dir)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在。")
    if task.status in {"paused", "completed", "failed"}:
        return RedirectResponse(url=f"/tasks/{run_id}", status_code=303)
    paused = pause_analysis_task(run_dir)
    if not paused:
        raise HTTPException(status_code=400, detail="当前任务无法暂停，可能已经结束。")
    return RedirectResponse(url=f"/tasks/{run_id}", status_code=303)


@app.get("/api/tasks/{run_id}")
async def read_task(run_id: str) -> dict:
    task = load_task(RUNS_DIR / run_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在。")
    view = _task_view(task)
    return {
        "run_id": view["run_id"],
        "parameter_name": view["parameter_name"],
        "status": view["status"],
        "progress": view["progress"],
        "current_step": view["current_step"],
        "error_message": view["error_message"],
        "error_raw_message": view["error_raw_message"],
        "result_ready": view["result_ready"],
        "created_at": display_datetime(task.created_at).isoformat(),
        "updated_at": display_datetime(task.updated_at).isoformat(),
    }


@app.get("/runs/{run_id}", response_class=HTMLResponse)
async def view_run(run_id: str, request: Request) -> HTMLResponse:
    run_dir = RUNS_DIR / run_id
    report = load_report(run_dir)
    if report is None:
        task = load_task(run_dir)
        if task is not None:
            return RedirectResponse(url=f"/tasks/{run_id}", status_code=303)
        raise HTTPException(status_code=404, detail="分析结果不存在。")
    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context=_build_result_context(request, report, run_dir),
    )


@app.post("/runs/{run_id}/decrypt", response_class=HTMLResponse)
async def decrypt_value(run_id: str, request: Request, ciphertext: str = Form(...)) -> HTMLResponse:
    run_dir = RUNS_DIR / run_id
    report = load_report(run_dir)
    if report is None:
        raise HTTPException(status_code=404, detail="分析结果不存在。")
    decrypt_result = None
    decrypt_error = None
    try:
        decrypt_result = _decrypt_with_script(run_dir, report, ciphertext.strip())
    except RuntimeError as exc:
        decrypt_error = str(exc)
    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context=_build_result_context(
            request,
            report,
            run_dir,
            decrypt_result=decrypt_result,
            decrypt_error=decrypt_error,
            submitted_ciphertext=ciphertext,
        ),
    )


@app.post("/runs/{run_id}/ask", response_class=HTMLResponse)
async def ask_followup(run_id: str, request: Request, question: str = Form(...)) -> HTMLResponse:
    run_dir = RUNS_DIR / run_id
    report = load_report(run_dir)
    if report is None:
        raise HTTPException(status_code=404, detail="分析结果不存在。")

    session = get_or_create_session(run_dir, report)
    analysis_request = load_analysis_request(run_dir)
    if analysis_request is None:
        raise HTTPException(status_code=400, detail="未找到原始分析请求，无法继续追问。")

    question = question.strip()
    followup_answer = None
    followup_error = None
    if not question:
        followup_error = "请输入需要继续追问的问题。"
    else:
        try:
            followup_answer = await answer_followup_with_llm(
                llm_config=_normalize_provider_config(analysis_request.llm),
                session_payload=build_followup_payload(report, session),
                user_question=question,
                debug_writer=_build_followup_debug_writer(run_dir),
            )
            session = append_session_exchange(
                run_dir,
                session,
                user_question=question,
                assistant_answer=followup_answer,
            )
        except LLMAnalysisError as exc:
            followup_error = exc.message

    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context=_build_result_context(
            request,
            report,
            run_dir,
            followup_question=question,
            followup_answer=followup_answer,
            followup_error=followup_error,
            session=session,
        ),
    )


@app.get("/runs/{run_id}/artifacts/{artifact_path:path}")
async def download_artifact(run_id: str, artifact_path: str) -> FileResponse:
    run_dir = RUNS_DIR / run_id
    target = (run_dir / artifact_path).resolve()
    if run_dir.resolve() not in target.parents and target != run_dir.resolve():
        raise HTTPException(status_code=400, detail="非法的产物路径。")
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="产物不存在。")
    media_type = "application/octet-stream"
    suffix = target.suffix.lower()
    if suffix == ".json":
        media_type = "application/json"
    elif suffix in {".py", ".js", ".txt", ".md"}:
        media_type = "text/plain"
    return FileResponse(path=target, media_type=media_type, filename=target.name)


@app.get("/api/runs/{run_id}")
async def read_run(run_id: str) -> dict:
    report = load_report(RUNS_DIR / run_id)
    if report is None:
        raise HTTPException(status_code=404, detail="分析结果不存在。")
    return json.loads(report.model_dump_json())


@app.get("/healthz")
async def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/favicon.ico")
async def favicon() -> Response:
    return Response(status_code=204)


def _build_result_context(
    request: Request,
    report: AnalysisReport,
    run_dir,
    *,
    decrypt_result: str | None = None,
    decrypt_error: str | None = None,
    submitted_ciphertext: str | None = None,
    followup_question: str | None = None,
    followup_answer: str | None = None,
    followup_error: str | None = None,
    session=None,
) -> dict:
    session = session or get_or_create_session(run_dir, report)
    artifact_files = [
        {"name": relative_name, "url": f"/runs/{report.run_id}/artifacts/{relative_name}"}
        for relative_name in report.generated_artifact.files
    ]
    llm_debug_files = _llm_debug_file_links(run_dir)
    success = _analysis_success(report)
    top_candidate = report.candidates[0] if report.candidates else None
    call_chain = report.llm.function_chain or (top_candidate.call_chain if top_candidate else [])
    key_material_items = _display_key_material(report)
    return {
        "report": report,
        "artifact_files": artifact_files,
        "llm_debug_files": llm_debug_files,
        "report_url": f"/runs/{report.run_id}/artifacts/report.json",
        "status_text": "分析成功" if success else "分析失败",
        "status_class": "success" if success else "failed",
        "status_summary": (
            "已经定位到目标参数的主要加密或编码流程。"
            if success
            else "暂未稳定恢复出可用的参数加密流程，请结合高级细节继续排查。"
        ),
        "reversibility_text": _reversibility_label(report.reversibility),
        "script_type_text": _script_type_label(report.generated_artifact.script_type),
        "validation_text": _validation_label(report.validation.status),
        "top_candidate": top_candidate,
        "call_chain": call_chain,
        "call_chain_text": _call_chain_text(call_chain),
        "can_decrypt": _can_decrypt(report),
        "decryptability_text": "支持纯 Python 在线解密" if _can_decrypt(report) else "当前不可在线解密",
        "decrypt_unavailable_reason": _decrypt_unavailable_reason(report),
        "operation_chain_text": _operation_chain_text(report, top_candidate),
        "key_material_items": key_material_items,
        "decrypt_result": decrypt_result,
        "decrypt_error": decrypt_error,
        "submitted_ciphertext": submitted_ciphertext or "",
        "session": session,
        "followup_question": followup_question or "",
        "followup_answer": followup_answer,
        "followup_error": followup_error,
    }


def _analysis_success(report: AnalysisReport) -> bool:
    if report.reversibility == "uncertain" and not report.llm.inferred_operations and not report.llm.key_material:
        return False
    return bool(
        report.candidates
        or report.llm.inferred_operations
        or report.llm.key_material
        or report.generated_artifact.script_type != "report-only"
    )


def _can_decrypt(report: AnalysisReport) -> bool:
    return (
        report.generated_artifact.script_type == "pure-python"
        and report.reversibility in {"potentially-reversible-encryption", "reversible-transform"}
    )


def _decrypt_unavailable_reason(report: AnalysisReport) -> str:
    if _can_decrypt(report):
        return ""
    conflict_note = next(
        (
            note
            for note in report.generated_artifact.notes
            if "模型结果存在自相矛盾" in note
        ),
        None,
    )
    if conflict_note:
        return conflict_note
    conflict_warning = next(
        (
            warning
            for warning in report.warnings
            if "模型结果仍存在自相矛盾" in warning
        ),
        None,
    )
    if conflict_warning:
        return conflict_warning
    if report.reversibility in {"potentially-reversible-encryption", "reversible-transform"}:
        if report.generated_artifact.script_type != "pure-python":
            return "本次结果虽然疑似可逆，但还没有生成稳定的纯 Python 解密脚本，因此暂不开放在线解密。"
        return "当前结果尚未满足在线解密所需的纯 Python 脚本条件。"
    return "本次结果更接近不可逆签名、摘要流程，或尚未恢复出稳定的可逆脚本。"


def _decrypt_with_script(run_dir, report: AnalysisReport, ciphertext: str) -> str:
    if not ciphertext:
        raise RuntimeError("请先输入需要解密的密文。")
    if not _can_decrypt(report):
        raise RuntimeError("当前分析结果不支持直接解密，可能属于不可逆签名或尚未恢复出可逆脚本。")
    script_path = run_dir / "artifacts" / "replay.py"
    if not script_path.exists():
        raise RuntimeError("未找到可执行的解密脚本。")
    result = subprocess.run(
        [sys.executable, str(script_path), "decrypt", ciphertext],
        cwd=str(script_path.parent),
        capture_output=True,
        text=True,
        timeout=25,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip() or "解密脚本执行失败。"
        raise RuntimeError(message)
    return result.stdout.strip()


def _task_view(task: TaskRecord, detail_mode: bool = False) -> dict:
    return {
        "run_id": task.run_id,
        "parameter_name": task.parameter_name,
        "status": task.status,
        "status_text": _task_status_label(task.status),
        "progress": task.progress,
        "current_step": task.current_step,
        "error_message": task.error_message,
        "error_raw_message": task.error_raw_message,
        "result_ready": task.result_ready,
        "created_at": format_datetime(task.created_at),
        "updated_at": format_datetime(task.updated_at),
        "open_url": f"/runs/{task.run_id}" if task.result_ready else f"/tasks/{task.run_id}",
        "can_delete": task.status in {"paused", "completed", "failed"},
        "can_pause": task.status in {"collecting", "queued", "running"},
        "draft_url": f"/?draft={task.run_id}",
        "detail_mode": detail_mode,
    }


def _llm_debug_file_links(run_dir) -> list[dict[str, str]]:
    return [
        {"name": relative_name.split("/")[-1], "path": relative_name, "url": f"/runs/{run_dir.name}/artifacts/{relative_name}"}
        for relative_name in list_artifact_paths(run_dir, prefix="artifacts/llm_debug/")
    ]


def _build_followup_debug_writer(run_dir):
    existing = list_artifact_paths(run_dir, prefix="artifacts/llm_debug/")
    counter = {"value": len(existing)}

    def writer(*, stage: str, name: str, payload: object) -> None:
        counter["value"] += 1
        relative_path = f"artifacts/llm_debug/{counter['value']:03d}_{stage}_{name}.json"
        from app.services.storage import save_artifact_json

        save_artifact_json(run_dir, relative_path, payload)

    return writer


def _saved_llm_view(saved_llm: LLMConfig) -> dict[str, str | bool | int]:
    provider_name = (saved_llm.provider_name or "deepseek").lower()
    return {
        "profile_name": saved_llm.profile_name or "",
        "provider_name": provider_name,
        "analysis_mode": saved_llm.analysis_mode or ("reasoner" if provider_name == "deepseek" else "glm"),
        "self_review_enabled": _resolve_llm_self_review_enabled(saved_llm),
        "glm_thinking_enabled": _resolve_glm_thinking_enabled(saved_llm, provider_name=provider_name),
        "base_url": saved_llm.base_url or (GLM_BASE_URL if provider_name == "glm" else DEEPSEEK_BASE_URL),
        "model_name": saved_llm.model_name or (GLM_DEFAULT_MODEL if provider_name == "glm" else DEEPSEEK_DEFAULT_MODEL),
        "api_key": saved_llm.api_key or "",
        "max_concurrency": _normalize_llm_concurrency(saved_llm.max_concurrency),
        "max_tokens": _normalize_llm_max_tokens(saved_llm.max_tokens),
        "system_prompt": saved_llm.system_prompt or DEFAULT_SYSTEM_PROMPT,
        "operator_prompt": saved_llm.operator_prompt or DEFAULT_OPERATOR_PROMPT,
        "has_saved": bool(saved_llm.base_url and saved_llm.model_name and saved_llm.api_key),
    }


def _task_status_label(status: str) -> str:
    return {
        "collecting": "收集源码中",
        "queued": "等待分析",
        "running": "分析中",
        "paused": "已暂停",
        "completed": "已完成",
        "failed": "失败",
    }.get(status, status)


def _reversibility_label(value: str) -> str:
    return {
        "potentially-reversible-encryption": "疑似可逆加密",
        "irreversible-signature-or-digest": "不可逆签名或摘要",
        "reversible-transform": "可逆编码或变换",
        "likely-irreversible-signature-or-token": "疑似不可逆签名或令牌",
        "uncertain": "暂不确定",
    }.get(value, value)


def _operation_chain_text(report: AnalysisReport, top_candidate) -> str:
    operations = [item for item in report.llm.inferred_operations if item]
    if operations:
        return " -> ".join(operations)
    if top_candidate and top_candidate.markers:
        return " -> ".join(top_candidate.markers)
    if report.flow_steps:
        return report.flow_steps[0]
    return "当前还未提炼出稳定的操作链。"


def _call_chain_text(call_chain: list[str]) -> str:
    if not call_chain:
        return "当前没有恢复出明确的函数调用链。"
    normalized: list[str] = []
    for item in call_chain:
        if "->" in item and " @ " not in item:
            parts = [part.strip() for part in item.split("->") if part.strip()]
            for part in parts:
                if not part.endswith(")"):
                    part = f"{part}()"
                normalized.append(part)
            continue
        function_name = item.split(" @ ", 1)[0].strip()
        if not function_name:
            continue
        if not function_name.endswith(")"):
            function_name = f"{function_name}()"
        normalized.append(function_name)
    if not normalized:
        return "当前没有恢复出明确的函数调用链。"
    return " -> ".join(normalized)


def _display_key_material(report: AnalysisReport) -> list[dict[str, str]]:
    raw_material = dict(report.llm.key_material)
    ordered_pairs = [
        ("seed_key", "原始 Key 种子"),
        ("seed_iv", "原始 IV 种子"),
        ("aes_key", "AES Key"),
        ("aes_key_bytes", "AES Key 字节长度"),
        ("aes_iv", "AES IV"),
        ("aes_iv_bytes", "AES IV 字节长度"),
        ("secret", "签名密钥"),
        ("aes_mode", "AES 模式"),
        ("output", "输出格式"),
        ("derivation_steps", "派生步骤"),
    ]
    items: list[dict[str, str]] = []
    for key, label in ordered_pairs:
        value = raw_material.get(key)
        if value:
            items.append({"label": label, "value": value})
    return items

def _script_type_label(value: str) -> str:
    return {
        "pure-python": "纯 Python 脚本",
        "report-only": "仅生成报告",
    }.get(value, value)


def _validation_label(value: str) -> str:
    return {
        "not_run": "未执行校验",
        "passed": "校验通过",
        "partial": "部分校验",
        "failed": "校验失败",
    }.get(value, value)


def _normalize_llm_concurrency(value: int | None) -> int:
    try:
        number = int(value or LLM_MAX_CONCURRENT_REQUESTS)
    except (TypeError, ValueError):
        number = LLM_MAX_CONCURRENT_REQUESTS
    return max(1, min(number, LLM_MAX_CONCURRENT_REQUESTS_LIMIT))


def _normalize_llm_max_tokens(value: int | None) -> int:
    try:
        number = int(value or LLM_DEFAULT_MAX_TOKENS)
    except (TypeError, ValueError):
        number = LLM_DEFAULT_MAX_TOKENS
    return max(LLM_MIN_MAX_TOKENS, min(number, LLM_MAX_TOKENS_LIMIT))


def _infer_analysis_mode(model_name: str | None) -> str:
    model = (model_name or "").lower()
    if model.startswith("glm"):
        return "glm"
    return "reasoner"


def _provider_presets() -> dict[str, dict[str, str | int | bool]]:
    return {
        "deepseek": {
            "label": "DeepSeek",
            "base_url": DEEPSEEK_BASE_URL,
            "model_name": DEEPSEEK_DEFAULT_MODEL,
            "max_tokens": DEEPSEEK_REASONER_DEFAULT_MAX_TOKENS,
            "analysis_mode": "reasoner",
            "model_readonly": True,
            "self_review_enabled": True,
            "glm_thinking_enabled": False,
        },
        "glm": {
            "label": "GLM",
            "base_url": GLM_BASE_URL,
            "model_name": GLM_DEFAULT_MODEL,
            "max_tokens": GLM_DEFAULT_MAX_TOKENS,
            "analysis_mode": "glm",
            "model_readonly": False,
            "self_review_enabled": True,
            "glm_thinking_enabled": True,
        },
    }


def _normalize_provider_config(llm_config: LLMConfig) -> LLMConfig:
    provider_name = (llm_config.provider_name or "deepseek").lower()
    provider_name = "glm" if provider_name == "glm" else "deepseek"
    base_url = llm_config.base_url or (GLM_BASE_URL if provider_name == "glm" else DEEPSEEK_BASE_URL)
    model_name = llm_config.model_name or (GLM_DEFAULT_MODEL if provider_name == "glm" else DEEPSEEK_DEFAULT_MODEL)
    analysis_mode = llm_config.analysis_mode or ("glm" if provider_name == "glm" else "reasoner")
    default_tokens = GLM_DEFAULT_MAX_TOKENS if provider_name == "glm" else DEEPSEEK_REASONER_DEFAULT_MAX_TOKENS
    max_tokens = _normalize_llm_max_tokens(llm_config.max_tokens or default_tokens)
    return LLMConfig(
        profile_name=llm_config.profile_name,
        provider_name=provider_name,
        base_url=base_url,
        model_name=model_name,
        api_key=llm_config.api_key,
        analysis_mode=analysis_mode,
        self_review_enabled=_resolve_llm_self_review_enabled(llm_config),
        glm_thinking_enabled=_resolve_glm_thinking_enabled(llm_config, provider_name=provider_name),
        max_concurrency=_normalize_llm_concurrency(llm_config.max_concurrency),
        max_tokens=max_tokens,
        system_prompt=llm_config.system_prompt or DEFAULT_SYSTEM_PROMPT,
        operator_prompt=llm_config.operator_prompt or DEFAULT_OPERATOR_PROMPT,
    )


def _load_supported_history():
    entries = load_llm_history(LLM_HISTORY_PATH)
    return [entry for entry in entries if _is_supported_provider(entry.llm)]


def _is_supported_provider(llm_config: LLMConfig) -> bool:
    provider = (llm_config.provider_name or "").lower()
    model_name = (llm_config.model_name or "").lower()
    base_url = (llm_config.base_url or "").lower()
    return (
        "deepseek" in provider
        or model_name.startswith("glm")
        or "deepseek" in model_name
        or "api.deepseek.com" in base_url
        or "bigmodel.cn" in base_url
        or provider == "glm"
        or not provider
    )


def _llm_history_view(entry, active_llm: LLMConfig) -> dict[str, object]:
    llm = _normalize_provider_config(entry.llm)
    is_current = (
        llm.provider_name == active_llm.provider_name
        and llm.base_url == active_llm.base_url
        and llm.model_name == active_llm.model_name
        and llm.api_key == active_llm.api_key
        and llm.analysis_mode == active_llm.analysis_mode
        and _resolve_llm_self_review_enabled(llm) == _resolve_llm_self_review_enabled(active_llm)
        and llm.glm_thinking_enabled == active_llm.glm_thinking_enabled
        and llm.max_tokens == active_llm.max_tokens
    )
    return {
        "entry_id": entry.entry_id,
        "profile_name": entry.profile_name,
        "provider_name": llm.provider_name or "deepseek",
        "model_name": llm.model_name or "",
        "analysis_mode": llm.analysis_mode or "reasoner",
        "self_review_enabled": _resolve_llm_self_review_enabled(llm),
        "glm_thinking_enabled": _resolve_glm_thinking_enabled(llm, provider_name=(llm.provider_name or "deepseek").lower()),
        "max_tokens": llm.max_tokens or LLM_DEFAULT_MAX_TOKENS,
        "max_concurrency": llm.max_concurrency or LLM_MAX_CONCURRENT_REQUESTS,
        "base_url": llm.base_url or DEEPSEEK_BASE_URL,
        "api_key_masked": mask_api_key(llm.api_key),
        "updated_at": format_datetime(entry.updated_at),
        "last_used_at": format_datetime(entry.last_used_at),
        "is_current": is_current,
        "config_payload": {
            "provider_name": llm.provider_name or "deepseek",
            "profile_name": llm.profile_name or entry.profile_name,
            "analysis_mode": llm.analysis_mode or "reasoner",
            "self_review_enabled": _resolve_llm_self_review_enabled(llm),
            "glm_thinking_enabled": _resolve_glm_thinking_enabled(llm, provider_name=(llm.provider_name or "deepseek").lower()),
            "base_url": llm.base_url or DEEPSEEK_BASE_URL,
            "model_name": llm.model_name or DEEPSEEK_DEFAULT_MODEL,
            "api_key": llm.api_key or "",
            "max_concurrency": llm.max_concurrency or LLM_MAX_CONCURRENT_REQUESTS,
            "max_tokens": llm.max_tokens or LLM_DEFAULT_MAX_TOKENS,
            "system_prompt": llm.system_prompt or DEFAULT_SYSTEM_PROMPT,
            "operator_prompt": llm.operator_prompt or DEFAULT_OPERATOR_PROMPT,
        },
    }


def _normalize_glm_thinking_mode(value: str | None) -> bool | None:
    text = (value or "").strip().lower()
    if not text:
        return None
    if text in {"enabled", "true", "1", "on", "yes"}:
        return True
    if text in {"disabled", "false", "0", "off", "no"}:
        return False
    return None


def _normalize_llm_self_review_mode(value: str | None) -> bool | None:
    text = (value or "").strip().lower()
    if not text:
        return None
    if text in {"enabled", "true", "1", "on", "yes"}:
        return True
    if text in {"disabled", "false", "0", "off", "no"}:
        return False
    return None


def _resolve_llm_self_review_enabled(llm_config: LLMConfig) -> bool:
    if llm_config.self_review_enabled is None:
        return True
    return bool(llm_config.self_review_enabled)


def _resolve_glm_thinking_enabled(llm_config: LLMConfig, *, provider_name: str | None = None) -> bool:
    provider = (provider_name or llm_config.provider_name or "deepseek").lower()
    if provider != "glm":
        return False
    if llm_config.glm_thinking_enabled is None:
        return True
    return bool(llm_config.glm_thinking_enabled)
