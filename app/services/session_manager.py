from __future__ import annotations

import re
from pathlib import Path

from app.models import AnalysisReport, AnalysisSession, AnalysisSessionMessage, AnalysisSessionSnippet
from app.services.storage import now_local


SESSION_FILENAME = "session.json"
MAX_FOLLOWUP_SNIPPETS = 4
MAX_FOLLOWUP_HISTORY_MESSAGES = 4
MAX_FOLLOWUP_HISTORY_CHARS = 900

FUNCTION_PATTERNS = [
    r"""function\s+{name}\s*\(""",
    r"""(?:const|let|var)\s+{name}\s*=\s*function\s*\(""",
    r"""(?:const|let|var)\s+{name}\s*=\s*(?:async\s*)?\([^)]*\)\s*=>""",
    r"""{name}\s*:\s*function\s*\(""",
]


def load_session(run_dir: Path) -> AnalysisSession | None:
    path = run_dir / SESSION_FILENAME
    if not path.exists():
        return None
    try:
        return AnalysisSession.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_session(run_dir: Path, session: AnalysisSession) -> None:
    path = run_dir / SESSION_FILENAME
    path.write_text(session.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")


def get_or_create_session(run_dir: Path, report: AnalysisReport) -> AnalysisSession:
    session = load_session(run_dir)
    if session is not None:
        return session
    session = build_session(run_dir, report)
    save_session(run_dir, session)
    return session


def append_session_exchange(
    run_dir: Path,
    session: AnalysisSession,
    *,
    user_question: str,
    assistant_answer: str,
) -> AnalysisSession:
    now = now_local()
    session.messages.append(
        AnalysisSessionMessage(role="user", content=user_question.strip(), created_at=now)
    )
    session.messages.append(
        AnalysisSessionMessage(role="assistant", content=assistant_answer.strip(), created_at=now)
    )
    session.updated_at = now
    save_session(run_dir, session)
    return session


def build_session(run_dir: Path, report: AnalysisReport) -> AnalysisSession:
    now = now_local()
    snippets = _build_session_snippets(run_dir, report)
    return AnalysisSession(
        run_id=report.run_id,
        created_at=now,
        updated_at=now,
        parameter_name=report.parameter_name,
        summary=report.summary,
        reversibility=report.reversibility,
        operation_chain=list(report.llm.inferred_operations),
        function_chain=list(report.llm.function_chain),
        observed_facts=list(report.llm.observed_facts),
        key_material=dict(report.llm.key_material),
        snippets=snippets,
        messages=[],
    )


def build_followup_payload(report: AnalysisReport, session: AnalysisSession) -> dict:
    return {
        "run_id": report.run_id,
        "parameter": {
            "name": report.parameter_name,
            "type": report.parameter_type,
            "location": report.parameter_location,
            "hint": report.parameter_hint,
            "api_context": report.api_context,
        },
        "report_summary": report.summary,
        "reversibility": report.reversibility,
        "operation_chain": list(report.llm.inferred_operations),
        "function_chain": list(report.llm.function_chain),
        "observed_facts": list(session.observed_facts or report.llm.observed_facts),
        "key_material": dict(report.llm.key_material),
        "flow_steps": list(report.flow_steps),
        "warnings": list(report.warnings),
        "session_snippets": [
            {
                "label": snippet.label,
                "file_name": snippet.file_name,
                "function_name": snippet.function_name,
                "line_hint": snippet.line_hint,
                "content": _trim_text(snippet.content, 1400),
            }
            for snippet in session.snippets[:MAX_FOLLOWUP_SNIPPETS]
        ],
        "conversation_history": [
            {"role": message.role, "content": _trim_text(message.content, MAX_FOLLOWUP_HISTORY_CHARS)}
            for message in session.messages[-MAX_FOLLOWUP_HISTORY_MESSAGES:]
        ],
    }


def _build_session_snippets(run_dir: Path, report: AnalysisReport) -> list[AnalysisSessionSnippet]:
    snippets: list[AnalysisSessionSnippet] = []
    normalized_dir = run_dir / "normalized"
    seen: set[str] = set()

    for ref in report.llm.selected_candidates[:8]:
        snippet = _snippet_from_reference(normalized_dir, ref)
        if snippet is None:
            continue
        key = f"{snippet.file_name}:{snippet.line_hint}:{snippet.function_name}:{snippet.label}"
        if key in seen:
            continue
        seen.add(key)
        snippets.append(snippet)

    for function_name in report.llm.function_chain[:6]:
        snippet = _snippet_from_function(normalized_dir, function_name)
        if snippet is None:
            continue
        key = f"{snippet.file_name}:{snippet.line_hint}:{snippet.function_name}:{snippet.label}"
        if key in seen:
            continue
        seen.add(key)
        snippets.append(snippet)

    replay_path = run_dir / "artifacts" / "replay.py"
    if replay_path.exists():
        content = replay_path.read_text(encoding="utf-8")
        snippets.append(
            AnalysisSessionSnippet(
                label="当前生成的 Python 复现脚本",
                file_name="artifacts/replay.py",
                function_name=None,
                line_hint=1,
                content=_trim_text(content, 1800),
            )
        )

    if not snippets:
        for source in report.sources[:2]:
            if not source.name:
                continue
            target = normalized_dir / source.name
            if not target.exists():
                continue
            snippets.append(
                AnalysisSessionSnippet(
                    label=f"补充源码片段：{source.name}",
                    file_name=source.name,
                    function_name=None,
                    line_hint=1,
                    content=_trim_text(target.read_text(encoding='utf-8'), 1800),
                )
            )
    return snippets[:10]


def _snippet_from_reference(normalized_dir: Path, reference: str) -> AnalysisSessionSnippet | None:
    file_name, line_hint = _parse_reference(reference)
    if not file_name:
        return None
    target = normalized_dir / file_name
    if not target.exists():
        return None
    lines = target.read_text(encoding="utf-8").splitlines()
    if line_hint is None:
        line_hint = 1
    return AnalysisSessionSnippet(
        label=f"重点定位：{file_name}:{line_hint}",
        file_name=file_name,
        function_name=None,
        line_hint=line_hint,
        content=_make_snippet(lines, line_hint, radius=14),
    )


def _snippet_from_function(normalized_dir: Path, function_name: str) -> AnalysisSessionSnippet | None:
    escaped = re.escape(function_name)
    compiled_patterns = [re.compile(pattern.format(name=escaped)) for pattern in FUNCTION_PATTERNS]
    for target in sorted(normalized_dir.glob("*")):
        if not target.is_file():
            continue
        lines = target.read_text(encoding="utf-8").splitlines()
        line_hint = None
        for index, line in enumerate(lines, start=1):
            if any(pattern.search(line) for pattern in compiled_patterns):
                line_hint = index
                break
        if line_hint is None:
            continue
        return AnalysisSessionSnippet(
            label=f"函数片段：{function_name}",
            file_name=target.name,
            function_name=function_name,
            line_hint=line_hint,
            content=_make_snippet(lines, line_hint, radius=18),
        )
    return None


def _parse_reference(reference: str) -> tuple[str | None, int | None]:
    if not reference or ":" not in reference:
        return None, None
    file_name, _, line_text = reference.partition(":")
    try:
        line_hint = int(line_text.strip())
    except (TypeError, ValueError):
        line_hint = None
    return file_name.strip() or None, line_hint


def _make_snippet(lines: list[str], line_number: int, radius: int = 12) -> str:
    start = max(0, line_number - radius - 1)
    end = min(len(lines), line_number + radius)
    return "\n".join(f"{index + 1:>5} | {lines[index]}" for index in range(start, end))


def _trim_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."
