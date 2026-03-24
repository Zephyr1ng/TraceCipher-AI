from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable

from app.models import AnalysisRequest, SourceArtifact
from app.services.analyzer import analyze_run
from app.services.llm import LLMAnalysisError
from app.services.storage import load_task, save_task, update_task


ACTIVE_TASKS: dict[str, asyncio.Task] = {}


def launch_analysis_task(
    *,
    run_dir: Path,
    analysis_request: AnalysisRequest,
    sources: list[SourceArtifact],
    ingestion_notes: list[str],
    ingestion_warnings: list[str],
) -> None:
    task = asyncio.create_task(
        _run_analysis_task(
            run_dir=run_dir,
            analysis_request=analysis_request,
            sources=sources,
            ingestion_notes=ingestion_notes,
            ingestion_warnings=ingestion_warnings,
        )
    )
    ACTIVE_TASKS[run_dir.name] = task
    task.add_done_callback(lambda _task: ACTIVE_TASKS.pop(run_dir.name, None))


def pause_analysis_task(run_dir: Path) -> bool:
    task = ACTIVE_TASKS.get(run_dir.name)
    if task is None:
        current = load_task(run_dir)
        if current is not None and current.status in {"collecting", "queued", "running"}:
            update_task(
                run_dir,
                status="paused",
                current_step="任务已暂停，可删除或作为草稿重新发起",
                error_message=None,
                error_raw_message=None,
                result_ready=False,
            )
            return True
        return False
    task.cancel("paused-by-user")
    return True


async def _run_analysis_task(
    *,
    run_dir: Path,
    analysis_request: AnalysisRequest,
    sources: list[SourceArtifact],
    ingestion_notes: list[str],
    ingestion_warnings: list[str],
) -> None:
    try:
        update_task(
            run_dir,
            status="running",
            progress=25,
            current_step="正在预处理源码并整理全量分析上下文",
        )
        report = await analyze_run(
            run_dir=run_dir,
            analysis_request=analysis_request,
            sources=sources,
            ingestion_notes=ingestion_notes,
            ingestion_warnings=ingestion_warnings,
            progress_callback=lambda progress, step: _safe_update_progress(run_dir, progress, step),
        )
        report_path = run_dir / "report.json"
        report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        update_task(
            run_dir,
            status="completed",
            progress=100,
            current_step="分析完成，可以查看结果",
            result_ready=True,
        )
    except asyncio.CancelledError:
        update_task(
            run_dir,
            status="paused",
            current_step="任务已暂停，可删除或作为草稿重新发起",
            error_message=None,
            error_raw_message=None,
            result_ready=False,
        )
        raise
    except LLMAnalysisError as exc:
        update_task(
            run_dir,
            status="failed",
            progress=100,
            current_step="模型分析失败",
            error_message=exc.message,
            error_raw_message=exc.raw_message,
            result_ready=False,
        )
    except Exception as exc:  # pragma: no cover - defensive task guard.
        update_task(
            run_dir,
            status="failed",
            progress=100,
            current_step="分析任务失败",
            error_message=str(exc),
            error_raw_message=str(exc),
            result_ready=False,
        )


def _safe_update_progress(run_dir: Path, progress: int, step: str) -> None:
    try:
        current = load_task(run_dir)
        if current is None or current.status in {"paused", "completed", "failed"}:
            return
        update_task(
            run_dir,
            status="running",
            progress=progress,
            current_step=step,
            result_ready=False,
        )
    except FileNotFoundError:
        return
