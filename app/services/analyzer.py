from __future__ import annotations

import math
import re
from pathlib import Path

try:
    import jsbeautifier
except ImportError:  # pragma: no cover - fallback is intentional.
    jsbeautifier = None

from app.models import AnalysisReport, AnalysisRequest, CandidateTrace, ValidationResult
from app.services.llm import analyze_with_llm, resolve_python_decryptability_with_llm, review_with_llm, survey_with_llm
from app.services.script_generator import generate_artifacts, validate_artifact
from app.services.storage import normalize_source_copy, now_local, save_artifact_json, source_summary


FUNCTION_PATTERNS = [
    re.compile(r"""function\s+([A-Za-z_$][\w$]*)\s*\("""),
    re.compile(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\("""),
    re.compile(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"""),
    re.compile(r"""([A-Za-z_$][\w$]*)\s*:\s*function\s*\("""),
    re.compile(r"""([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?\([^)]*\)\s*=>"""),
]

MARKER_PATTERNS = {
    "md5": [r"\bmd5\b"],
    "sha1": [r"\bsha1\b"],
    "sha256": [r"\bsha256\b"],
    "sha512": [r"\bsha512\b"],
    "hmac": [r"\bhmac\b", r"HmacSHA"],
    "aes": [r"CryptoJS\.AES", r"AES\.encrypt", r"AES\.decrypt", r"mode\.CBC", r"mode\.ECB"],
    "base64": [r"\bbtoa\b", r"\batob\b", r"Base64", r"base64"],
    "urlencode": [r"encodeURIComponent", r"decodeURIComponent"],
    "json": [r"JSON\.stringify", r"JSON\.parse"],
    "rsa": [r"JSEncrypt", r"setPublicKey", r"privateDecrypt", r"RSA"],
}

REQUEST_PATTERNS = {
    "fetch": r"\bfetch\s*\(",
    "axios": r"\baxios\b",
    "ajax": r"\$\.ajax|\bajax\s*\(",
    "xhr": r"XMLHttpRequest",
    "headers": r"\bheaders\b",
    "body": r"\bbody\b",
    "query": r"\bparams\b|\bquery\b",
    "login": r"\blogin\b|\bpassword\b|\bpasswd\b",
}

IGNORED_CALLS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "function",
    "return",
    "Object",
    "Array",
    "String",
    "Number",
    "Boolean",
    "Date",
    "Promise",
    "Math",
    "console",
    "JSON",
    "parseInt",
    "parseFloat",
    "encodeURIComponent",
    "decodeURIComponent",
    "btoa",
    "atob",
    "require",
}


async def analyze_run(
    *,
    run_dir: Path,
    analysis_request: AnalysisRequest,
    sources: list,
    ingestion_notes: list[str],
    ingestion_warnings: list[str],
    progress_callback=None,
) -> AnalysisReport:
    debug_writer = _build_llm_debug_writer(run_dir)
    normalized_sources = []
    source_contents: dict[str, str] = {}
    _notify_progress(progress_callback, 30, "正在格式化与标准化源码")
    for source in sources:
        normalized_content = _normalize_js(source.content)
        normalize_source_copy(run_dir, source, normalized_content)
        source.content = normalized_content
        source_contents[source.name] = normalized_content
        normalized_sources.append(source)

    _notify_progress(progress_callback, 40, "正在整理第一阶段全量源码上下文")
    survey_context_blocks = _build_survey_llm_context(normalized_sources, analysis_request)
    llm_source_summaries = [
        {
            "name": source.name,
            "origin": source.origin,
            "source_url": source.source_url,
            "notes": source.notes[:3],
        }
        for source in normalized_sources[:20]
    ]

    _notify_progress(progress_callback, 52, "正在执行第一阶段全量通读")
    analysis_overview = await survey_with_llm(
        llm_config=analysis_request.llm,
        parameter_name=analysis_request.parameter_name,
        parameter_type=analysis_request.parameter_type,
        parameter_location=analysis_request.parameter_location,
        parameter_hint=analysis_request.parameter_hint,
        api_context=analysis_request.api_context,
        webpage_url=analysis_request.webpage_url,
        source_summaries=llm_source_summaries,
        context_blocks=survey_context_blocks,
        debug_writer=debug_writer,
    )

    _notify_progress(progress_callback, 63, "正在整理第二阶段聚焦精读上下文")
    focused_context_blocks = _build_focused_llm_context(normalized_sources, analysis_request, analysis_overview)

    _notify_progress(progress_callback, 74, "正在执行第二阶段精读与最终判断")
    llm_insight = await analyze_with_llm(
        llm_config=analysis_request.llm,
        parameter_name=analysis_request.parameter_name,
        parameter_type=analysis_request.parameter_type,
        parameter_location=analysis_request.parameter_location,
        parameter_hint=analysis_request.parameter_hint,
        api_context=analysis_request.api_context,
        webpage_url=analysis_request.webpage_url,
        validation_plaintext=analysis_request.validation_plaintext,
        validation_ciphertext=analysis_request.validation_ciphertext,
        source_summaries=llm_source_summaries,
        context_blocks=focused_context_blocks,
        analysis_overview=analysis_overview,
        debug_writer=debug_writer,
    )
    _hydrate_llm_insight_from_overview(llm_insight, analysis_overview)
    self_review_enabled = _llm_self_review_enabled(analysis_request.llm)
    audit_reasons = _llm_self_review_reasons(llm_insight)
    if self_review_enabled and audit_reasons:
        _notify_progress(progress_callback, 82, "正在执行模型自审查与结果复核")
        llm_insight = await review_with_llm(
            llm_config=analysis_request.llm,
            parameter_name=analysis_request.parameter_name,
            parameter_type=analysis_request.parameter_type,
            parameter_location=analysis_request.parameter_location,
            parameter_hint=analysis_request.parameter_hint,
            api_context=analysis_request.api_context,
            webpage_url=analysis_request.webpage_url,
            source_summaries=llm_source_summaries,
            context_blocks=focused_context_blocks,
            initial_insight=llm_insight,
            audit_reasons=audit_reasons,
            debug_writer=debug_writer,
        )
        _hydrate_llm_insight_from_overview(llm_insight, analysis_overview)
    conflict_reasons = _llm_python_decryptability_conflict_reasons(llm_insight)
    if self_review_enabled and conflict_reasons:
        _notify_progress(progress_callback, 86, "正在执行关键材料一致性复核")
        llm_insight = await resolve_python_decryptability_with_llm(
            llm_config=analysis_request.llm,
            parameter_name=analysis_request.parameter_name,
            parameter_type=analysis_request.parameter_type,
            parameter_location=analysis_request.parameter_location,
            parameter_hint=analysis_request.parameter_hint,
            api_context=analysis_request.api_context,
            webpage_url=analysis_request.webpage_url,
            source_summaries=llm_source_summaries,
            context_blocks=focused_context_blocks,
            initial_insight=llm_insight,
            audit_reasons=conflict_reasons,
            debug_writer=debug_writer,
        )
        _hydrate_llm_insight_from_overview(llm_insight, analysis_overview)
    remaining_conflicts = _llm_python_decryptability_conflict_reasons(llm_insight)
    if not self_review_enabled and (audit_reasons or conflict_reasons):
        llm_insight.warnings.append("当前已关闭模型自审查与结果复核，结果未经过自动纠错，可能保留未消除的字段冲突。")
    elif remaining_conflicts:
        llm_insight.warnings.append(
            "模型结果仍存在自相矛盾：已判断为可逆且倾向 pure-python，但关键材料或脚本条件仍不满足要求，需要人工复核。"
        )

    reversibility = llm_insight.reversibility or _classify_reversibility_from_llm(llm_insight, analysis_request.parameter_type)
    confidence = llm_insight.confidence if llm_insight.confidence is not None else _default_confidence(llm_insight)
    flow_steps = llm_insight.flow_steps or _build_llm_fallback_steps(analysis_request.parameter_name, reversibility)

    _notify_progress(progress_callback, 90, "正在生成脚本与分析产物")
    generated_artifact, generation_context = generate_artifacts(
        run_dir=run_dir,
        parameter_name=analysis_request.parameter_name,
        parameter_type=analysis_request.parameter_type,
        reversibility=reversibility,
        candidates=[],
        source_contents=source_contents,
        llm_insight=llm_insight,
    )
    _notify_progress(progress_callback, 96, "正在校验分析结果")
    validation_status, validation_details = validate_artifact(
        validation_plaintext=analysis_request.validation_plaintext,
        validation_ciphertext=analysis_request.validation_ciphertext,
        generation_context=generation_context,
    )
    validation = ValidationResult(status=validation_status, details=validation_details)

    warnings = list(ingestion_warnings)
    warnings.extend(_analysis_warnings(llm_insight, generated_artifact.script_type))
    warnings.extend(llm_insight.warnings)

    summary = _build_summary(
        parameter_name=analysis_request.parameter_name,
        parameter_type=analysis_request.parameter_type,
        reversibility=reversibility,
        llm_summary=llm_insight.summary,
    )

    return AnalysisReport(
        run_id=run_dir.name,
        created_at=now_local(),
        parameter_name=analysis_request.parameter_name,
        parameter_type=analysis_request.parameter_type,
        parameter_location=analysis_request.parameter_location,
        parameter_hint=analysis_request.parameter_hint,
        api_context=analysis_request.api_context,
        webpage_url=analysis_request.webpage_url,
        external_js_urls=analysis_request.external_js_urls,
        summary=summary,
        reversibility=reversibility,
        confidence=confidence,
        sources=[source_summary(source) for source in normalized_sources],
        flow_steps=_merge_unique(ingestion_notes, flow_steps),
        candidates=[],
        generated_artifact=generated_artifact,
        validation=validation,
        llm=llm_insight,
        warnings=warnings,
    )


def _normalize_js(content: str) -> str:
    if jsbeautifier is None:
        return content
    options = jsbeautifier.default_options()
    options.indent_size = 2
    options.keep_array_indentation = False
    options.wrap_line_length = 120
    try:
        return jsbeautifier.beautify(content, options)
    except Exception:
        return content


def _build_llm_debug_writer(run_dir: Path):
    counter = {"value": 0}

    def writer(*, stage: str, name: str, payload: object) -> None:
        counter["value"] += 1
        relative_path = f"artifacts/llm_debug/{counter['value']:03d}_{stage}_{name}.json"
        save_artifact_json(run_dir, relative_path, payload)

    return writer


def _scan_source(source, analysis_request: AnalysisRequest) -> list[CandidateTrace]:
    lines = source.content.splitlines()
    parameter_name = analysis_request.parameter_name
    parameter_name_lower = parameter_name.lower()
    hint_tokens = _tokenize(analysis_request.parameter_hint)
    api_tokens = _tokenize(analysis_request.api_context)
    candidates: list[CandidateTrace] = []

    for index, line in enumerate(lines, start=1):
        lower_line = line.lower()
        score = 0.0
        reasons: list[str] = []
        if parameter_name_lower in lower_line:
            score += 10
            reasons.append("命中了目标参数名。")
            if re.search(rf"""["']?{re.escape(parameter_name)}["']?\s*:""", line):
                score += 7
                reasons.append("参数出现在对象键或请求字段位置。")
            if re.search(rf"""\b{re.escape(parameter_name)}\b\s*=""", line):
                score += 5
                reasons.append("参数出现在赋值语句左侧。")
        if hint_tokens and any(token in lower_line for token in hint_tokens):
            score += 2
            reasons.append("补充说明与该代码区域匹配。")
        if api_tokens and any(token in lower_line for token in api_tokens):
            score += 4
            reasons.append("接口上下文与该代码区域匹配。")
        request_clues = _detect_request_clues(line)
        if request_clues:
            score += len(request_clues) * 1.5
            reasons.append("附近存在请求构造线索。")
        if score <= 0:
            continue

        function_name, function_line = _find_enclosing_function(lines, index)
        function_body = _extract_function_body(lines, function_line) if function_line else []
        snippet = _make_snippet(lines, index)
        markers = _detect_markers("\n".join(function_body) or snippet)
        if markers:
            score += len(markers) * 3
            reasons.append("所在函数内出现了加密、摘要或编码标记。")
        call_chain = _build_call_chain(lines, function_name, function_line, function_body)
        summary = _candidate_summary(function_name, markers, request_clues)
        candidates.append(
            CandidateTrace(
                file_name=source.name,
                source_url=source.source_url,
                line_number=index,
                function_name=function_name,
                function_line=function_line,
                score=round(score, 2),
                markers=markers,
                reasons=reasons,
                request_clues=request_clues,
                snippet=snippet,
                function_excerpt=_format_function_excerpt(function_line, function_body),
                call_chain=call_chain,
                summary=summary,
            )
        )

    candidates.extend(_scan_crypto_functions(source, analysis_request, lines))
    candidates = _dedupe_candidates(candidates)

    if candidates:
        return candidates

    return _fallback_scan(source, analysis_request)


def _fallback_scan(source, analysis_request: AnalysisRequest) -> list[CandidateTrace]:
    lines = source.content.splitlines()
    hint_tokens = _tokenize(analysis_request.parameter_hint) + _tokenize(analysis_request.api_context)
    if not hint_tokens:
        return []
    candidates: list[CandidateTrace] = []
    for index, line in enumerate(lines, start=1):
        lower_line = line.lower()
        matched = [token for token in hint_tokens if token in lower_line]
        if not matched:
            continue
        request_clues = _detect_request_clues(line)
        markers = _detect_markers(_make_snippet(lines, index))
        if not request_clues and not markers:
            continue
        function_name, function_line = _find_enclosing_function(lines, index)
        function_body = _extract_function_body(lines, function_line) if function_line else []
        candidates.append(
            CandidateTrace(
                file_name=source.name,
                source_url=source.source_url,
                line_number=index,
                function_name=function_name,
                function_line=function_line,
                score=round(4 + len(matched) + len(markers) * 1.5 + len(request_clues), 2),
                markers=markers,
                reasons=["通过补充说明或接口上下文做了回退命中。"],
                request_clues=request_clues,
                snippet=_make_snippet(lines, index),
                function_excerpt=_format_function_excerpt(function_line, function_body),
                call_chain=_build_call_chain(lines, function_name, function_line, function_body),
                summary="这是通过补充说明和接口上下文回退得到的候选位置。",
            )
        )
    return candidates


def _scan_crypto_functions(source, analysis_request: AnalysisRequest, lines: list[str]) -> list[CandidateTrace]:
    parameter_name = analysis_request.parameter_name.lower()
    hint_tokens = _tokenize(analysis_request.parameter_hint)
    api_tokens = _tokenize(analysis_request.api_context)
    candidates: list[CandidateTrace] = []
    seen_functions: set[tuple[str, int]] = set()

    for index, line in enumerate(lines, start=1):
        function_name, function_line = _find_enclosing_function(lines, index)
        if not function_name or not function_line or (function_name, function_line) in seen_functions:
            continue
        function_body = _extract_function_body(lines, function_line)
        if not function_body:
            continue
        function_text = "\n".join(function_body)
        markers = _detect_markers(function_text)
        if not markers:
            continue
        lower_text = function_text.lower()
        request_clues = _detect_request_clues(function_text)
        score = 6 + len(markers) * 3 + len(request_clues) * 1.2
        reasons = ["函数体内存在明确的加密、摘要或编码标记。"]
        if parameter_name and parameter_name in lower_text:
            score += 5
            reasons.append("函数体内直接出现了目标参数名。")
        if hint_tokens and any(token in lower_text for token in hint_tokens):
            score += 2
            reasons.append("函数体与参数补充说明匹配。")
        if api_tokens and any(token in lower_text for token in api_tokens):
            score += 2
            reasons.append("函数体与接口上下文匹配。")

        seen_functions.add((function_name, function_line))
        candidates.append(
            CandidateTrace(
                file_name=source.name,
                source_url=source.source_url,
                line_number=function_line,
                function_name=function_name,
                function_line=function_line,
                score=round(score, 2),
                markers=markers,
                reasons=reasons,
                request_clues=request_clues,
                snippet=_make_snippet(lines, function_line, radius=10),
                function_excerpt=_format_function_excerpt(function_line, function_body),
                call_chain=_build_call_chain(lines, function_name, function_line, function_body),
                summary="这是按函数体中的加密标记提取出的辅助候选，用于帮助大模型阅读真实加密逻辑。",
            )
        )
    return candidates


def _dedupe_candidates(candidates: list[CandidateTrace]) -> list[CandidateTrace]:
    best_by_ref: dict[tuple[str, int], CandidateTrace] = {}
    for candidate in candidates:
        key = (candidate.file_name, candidate.line_number)
        existing = best_by_ref.get(key)
        if existing is None or candidate.score > existing.score:
            best_by_ref[key] = candidate
    return list(best_by_ref.values())


def _tokenize(text: str | None) -> list[str]:
    if not text:
        return []
    return [token for token in re.split(r"[^A-Za-z0-9_]+", text.lower()) if len(token) >= 3]


def _detect_markers(text: str) -> list[str]:
    markers: list[str] = []
    for marker, patterns in MARKER_PATTERNS.items():
        if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns):
            markers.append(marker)
    return markers


def _detect_request_clues(text: str) -> list[str]:
    clues: list[str] = []
    for name, pattern in REQUEST_PATTERNS.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            clues.append(name)
    return clues


def _source_marker_summary(sources: list) -> set[str]:
    markers: set[str] = set()
    for source in sources:
        content = source.content or ""
        markers.update(_detect_markers(content))
        if "_0x" in content or re.search(r"""0x[a-f0-9]{3,}""", content, flags=re.IGNORECASE):
            markers.add("obfuscated")
        if re.search(r"""\[[^\]]{30,}\]\s*\[\s*\w+\s*-\s*\d+\s*\]""", content):
            markers.add("dispatcher")
        if re.search(r"""(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*\[\s*["']""", content):
            markers.add("string_table")
    return markers


def _find_enclosing_function(lines: list[str], line_number: int) -> tuple[str | None, int | None]:
    for index in range(line_number - 1, -1, -1):
        line = lines[index]
        for pattern in FUNCTION_PATTERNS:
            match = pattern.search(line)
            if match:
                return match.group(1), index + 1
    return None, None


def _extract_function_body(lines: list[str], function_line: int | None, max_lines: int = 220) -> list[str]:
    if function_line is None:
        return []
    start_index = function_line - 1
    body: list[str] = []
    depth = 0
    started = False
    for index in range(start_index, min(len(lines), start_index + max_lines)):
        line = lines[index]
        body.append(line)
        depth += line.count("{")
        if line.count("{") > 0:
            started = True
        depth -= line.count("}")
        if started and depth <= 0:
            break
    return body


def _build_call_chain(
    lines: list[str],
    function_name: str | None,
    function_line: int | None,
    function_body: list[str],
) -> list[str]:
    chain: list[str] = []
    if function_name and function_line:
        chain.append(f"{function_name} @ 第 {function_line} 行")
    if not function_body:
        return chain
    joined = "\n".join(function_body)
    callees = re.findall(r"""(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(""", joined)
    seen: set[str] = set()
    for callee in callees:
        if callee in IGNORED_CALLS or callee == function_name or callee in seen:
            continue
        seen.add(callee)
        callee_line = _find_function_definition(lines, callee)
        if callee_line:
            chain.append(f"{callee} @ 第 {callee_line} 行")
        else:
            chain.append(callee)
        if len(chain) >= 6:
            break
    return chain


def _find_function_definition(lines: list[str], function_name: str) -> int | None:
    escaped = re.escape(function_name)
    patterns = [
        re.compile(rf"""function\s+{escaped}\s*\("""),
        re.compile(rf"""(?:const|let|var)\s+{escaped}\s*=\s*function\s*\("""),
        re.compile(rf"""(?:const|let|var)\s+{escaped}\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"""),
        re.compile(rf"""{escaped}\s*:\s*function\s*\("""),
    ]
    for index, line in enumerate(lines, start=1):
        if any(pattern.search(line) for pattern in patterns):
            return index
    return None


def _make_snippet(lines: list[str], line_number: int, radius: int = 6) -> str:
    start = max(0, line_number - radius - 1)
    end = min(len(lines), line_number + radius)
    snippet_lines = []
    for index in range(start, end):
        snippet_lines.append(f"{index + 1:>5} | {lines[index]}")
    return "\n".join(snippet_lines)


def _candidate_summary(function_name: str | None, markers: list[str], request_clues: list[str]) -> str:
    if function_name and markers:
        return f"函数 {function_name} 同时包含加密标记与请求构造线索，是高优先级候选。"
    if function_name:
        return f"函数 {function_name} 很可能参与了参数组装或发送。"
    return "该位置很可能参与了参数组装，但暂未稳定恢复到函数定义。"


def _classify_reversibility_from_llm(llm_insight, parameter_type: str) -> str:
    markers = set(llm_insight.inferred_operations)
    if markers & {"md5", "sha1", "sha256", "sha512", "hmac"}:
        return "irreversible-signature-or-digest"
    if markers & {"aes", "rsa"}:
        return "potentially-reversible-encryption"
    if markers & {"base64", "urlencode", "json", "hex"}:
        return "reversible-transform"
    if parameter_type.lower() in {"signature", "sign", "token"}:
        return "likely-irreversible-signature-or-token"
    return "uncertain"


def _default_confidence(llm_insight) -> float:
    if llm_insight.key_material:
        return 0.88
    if llm_insight.inferred_operations and llm_insight.function_chain:
        return 0.82
    if llm_insight.inferred_operations:
        return 0.72
    return 0.45


def _build_llm_fallback_steps(parameter_name: str, reversibility: str) -> list[str]:
    return [
        f'大模型已经完成对参数“{parameter_name}”相关源码的整体验读。',
        "当前没有返回更细的步骤拆解，建议结合函数调用链与关键材料查看结果。",
        f"当前对该流程的可逆性判断为：{_reversibility_text(reversibility)}。",
    ]


def _analysis_warnings(llm_insight, script_type: str) -> list[str]:
    warnings: list[str] = []
    if not llm_insight.inferred_operations and not llm_insight.function_chain:
        warnings.append("大模型尚未稳定返回明确的函数链或操作链，建议补充更多相关源码后重试。")
    if script_type != "pure-python":
        warnings.append("当前未能仅凭静态分析恢复出稳定的纯 Python 复现路径。")
    return warnings


def _build_survey_llm_context(sources: list, analysis_request: AnalysisRequest) -> list[dict]:
    blocks: list[dict] = []
    blocks.append(
        {
            "block_type": "analysis_goal",
            "goal": {
                "parameter_name": analysis_request.parameter_name,
                "parameter_type": analysis_request.parameter_type,
                "parameter_location": analysis_request.parameter_location,
                "parameter_hint": analysis_request.parameter_hint,
                "api_context": analysis_request.api_context,
                "expectation": "先通读全部源码，再定位真实的参数加密函数、密钥派生函数、请求组装函数和最终参数落点。",
            },
        }
    )

    total_budget, per_file_budget = _context_budgets_for_model(analysis_request)
    remaining_budget = total_budget
    for source in sources:
        if remaining_budget <= 0:
            break
        content_block = _trim_text(source.content, min(per_file_budget, remaining_budget))
        blocks.append(
            {
                "block_type": "full_source",
                "file": source.name,
                "origin": source.origin,
                "source_url": source.source_url,
                "content_markers": _detect_markers(source.content),
                "function_index": _list_functions_with_lines(source.content.splitlines()),
                "content": content_block,
            }
        )
        remaining_budget -= len(content_block)

    return blocks


def _build_focused_llm_context(sources: list, analysis_request: AnalysisRequest, analysis_overview: dict) -> list[dict]:
    blocks: list[dict] = [
        {
            "block_type": "analysis_goal",
            "goal": {
                "parameter_name": analysis_request.parameter_name,
                "parameter_type": analysis_request.parameter_type,
                "parameter_location": analysis_request.parameter_location,
                "parameter_hint": analysis_request.parameter_hint,
                "api_context": analysis_request.api_context,
                "expectation": "这是第二阶段精读，请重点核对真实加密函数、密钥派生函数、请求组装函数和最终参数落点。",
            },
        },
        {
            "block_type": "stage_one_overview",
            "global_summary": analysis_overview.get("global_summary"),
            "relevant_files": analysis_overview.get("relevant_files", []),
            "suspected_function_chain": analysis_overview.get("suspected_function_chain", []),
            "suspected_operations": analysis_overview.get("suspected_operations", []),
            "reasoning_notes": analysis_overview.get("reasoning_notes", []),
        },
    ]

    focus_blocks = _focus_target_blocks(sources, analysis_overview.get("focus_targets", []))
    blocks.extend(focus_blocks)

    function_blocks = _function_chain_blocks(sources, analysis_overview.get("suspected_function_chain", []))
    existing_refs = {(block.get("file"), block.get("function_name")) for block in blocks if isinstance(block, dict)}
    for block in function_blocks:
        ref = (block.get("file"), block.get("function_name"))
        if ref in existing_refs:
            continue
        blocks.append(block)
        existing_refs.add(ref)

    relevant_files = [item for item in analysis_overview.get("relevant_files", []) if item]
    related_sources = _pick_sources_by_name(sources, relevant_files)
    if not related_sources:
        related_sources = _fallback_focus_sources(sources, analysis_request)
    total_budget, per_source_budget = _focused_context_budgets_for_request(analysis_request)
    remaining_budget = total_budget
    for source in related_sources[:4]:
        if remaining_budget <= 0:
            break
        excerpt = _trim_text(source.content, min(per_source_budget, remaining_budget))
        blocks.append(
            {
                "block_type": "focused_full_source",
                "file": source.name,
                "origin": source.origin,
                "source_url": source.source_url,
                "content_markers": _detect_markers(source.content),
                "function_index": _list_functions_with_lines(source.content.splitlines(), max_items=60),
                "content": excerpt,
            }
        )
        remaining_budget -= len(excerpt)

    return blocks


def _context_budgets_for_model(analysis_request: AnalysisRequest) -> tuple[int, int]:
    model_name = (analysis_request.llm.model_name or "").lower()
    provider_name = (analysis_request.llm.provider_name or "").lower()
    if provider_name == "glm" or model_name.startswith("glm"):
        return (36000, 9000)
    if "reasoner" in model_name:
        return (92000, 18000)
    return (68000, 12000)


def _focused_context_budgets_for_request(analysis_request: AnalysisRequest) -> tuple[int, int]:
    model_name = (analysis_request.llm.model_name or "").lower()
    provider_name = (analysis_request.llm.provider_name or "").lower()
    if provider_name == "glm" or model_name.startswith("glm"):
        return (24000, 8000)
    if "reasoner" in model_name:
        return (42000, 12000)
    return (30000, 10000)


def _focus_target_blocks(sources: list, focus_targets: list[dict]) -> list[dict]:
    if not focus_targets:
        return []

    by_name = {source.name: source for source in sources}
    blocks: list[dict] = []
    seen: set[str] = set()
    for target in focus_targets[:10]:
        file_name = (target.get("file") or "").strip()
        source = by_name.get(file_name)
        if source is None:
            source = _find_source_by_suffix(sources, file_name)
        if source is None:
            continue

        lines = source.content.splitlines()
        line_hint = target.get("line_hint")
        function_name = (target.get("function_name") or "").strip() or None
        if function_name:
            function_line = _find_function_definition(lines, function_name)
        else:
            function_line = line_hint if isinstance(line_hint, int) else None
        if function_line is None and isinstance(line_hint, int):
            function_line = line_hint
        if function_line is None and function_name is None:
            continue

        reference = f"{source.name}:{function_line or 0}:{function_name or ''}"
        if reference in seen:
            continue
        seen.add(reference)

        excerpt_line = function_line or 1
        snippet = _make_snippet(lines, excerpt_line, radius=14)
        enclosing_function, enclosing_line = _find_enclosing_function(lines, excerpt_line)
        focus_name = function_name or enclosing_function
        focus_line = function_line or enclosing_line
        function_body = _extract_function_body(lines, focus_line) if focus_line else []
        blocks.append(
            {
                "block_type": "focus_target",
                "file": source.name,
                "source_url": source.source_url,
                "line_hint": line_hint,
                "function_name": focus_name,
                "reason": target.get("reason"),
                "snippet": snippet,
                "function_excerpt": _format_function_excerpt(focus_line, function_body),
                "content_markers": _detect_markers("\n".join(function_body) or snippet),
            }
        )
    return blocks


def _function_chain_blocks(sources: list, function_chain: list[str]) -> list[dict]:
    if not function_chain:
        return []

    blocks: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for function_name in function_chain[:10]:
        for source in sources:
            lines = source.content.splitlines()
            function_line = _find_function_definition(lines, function_name)
            if function_line is None:
                continue
            key = (source.name, function_name)
            if key in seen:
                continue
            seen.add(key)
            function_body = _extract_function_body(lines, function_line)
            blocks.append(
                {
                    "block_type": "function_chain_target",
                    "file": source.name,
                    "source_url": source.source_url,
                    "function_name": function_name,
                    "function_line": function_line,
                    "function_excerpt": _format_function_excerpt(function_line, function_body),
                    "content_markers": _detect_markers("\n".join(function_body)),
                }
            )
    return blocks


def _pick_sources_by_name(sources: list, names: list[str]) -> list:
    if not names:
        return []
    selected = []
    seen: set[str] = set()
    for name in names:
        source = _find_source_by_suffix(sources, name)
        if source is None or source.name in seen:
            continue
        seen.add(source.name)
        selected.append(source)
    return selected


def _find_source_by_suffix(sources: list, target_name: str):
    if not target_name:
        return None
    normalized = target_name.strip()
    for source in sources:
        if source.name == normalized or source.name.endswith(normalized):
            return source
    return None


def _fallback_focus_sources(sources: list, analysis_request: AnalysisRequest) -> list:
    hint_tokens = [analysis_request.parameter_name.lower(), *_tokenize(analysis_request.parameter_hint), *_tokenize(analysis_request.api_context)]
    scored: list[tuple[float, object]] = []
    for source in sources:
        content_lower = source.content.lower()
        score = 0.0
        if any(token and token in content_lower for token in hint_tokens):
            score += 3
        score += len(_detect_markers(source.content)) * 2
        score += len(_detect_request_clues(source.content))
        scored.append((score, source))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [source for score, source in scored if score > 0][:4] or sources[:2]


def _hydrate_llm_insight_from_overview(llm_insight, analysis_overview: dict) -> None:
    if not llm_insight.summary and analysis_overview.get("global_summary"):
        llm_insight.summary = analysis_overview.get("global_summary")
    if not llm_insight.function_chain and analysis_overview.get("suspected_function_chain"):
        llm_insight.function_chain = list(analysis_overview.get("suspected_function_chain", []))
    if not llm_insight.inferred_operations and analysis_overview.get("suspected_operations"):
        llm_insight.inferred_operations = list(analysis_overview.get("suspected_operations", []))
    if not llm_insight.reasoning_notes and analysis_overview.get("reasoning_notes"):
        llm_insight.reasoning_notes = list(analysis_overview.get("reasoning_notes", []))
    if not llm_insight.selected_candidates:
        refs = []
        for target in analysis_overview.get("focus_targets", []):
            file_name = (target.get("file") or "").strip()
            line_hint = target.get("line_hint")
            if file_name and isinstance(line_hint, int):
                refs.append(f"{file_name}:{line_hint}")
        llm_insight.selected_candidates = refs[:8]


def _prioritize_candidates(candidates: list[CandidateTrace], selected_references: list[str]) -> list[CandidateTrace]:
    if not selected_references:
        return candidates
    normalized_refs = {reference.strip() for reference in selected_references if reference.strip()}
    selected: list[CandidateTrace] = []
    remaining: list[CandidateTrace] = []
    for candidate in candidates:
        ref = f"{candidate.file_name}:{candidate.line_number}"
        if ref in normalized_refs:
            selected.append(candidate)
        else:
            remaining.append(candidate)
    return selected + remaining


def _format_function_excerpt(function_line: int | None, function_body: list[str]) -> str | None:
    if function_line is None or not function_body:
        return None
    excerpt_lines = []
    for offset, line in enumerate(function_body[:120], start=function_line):
        excerpt_lines.append(f"{offset:>5} | {line}")
    return "\n".join(excerpt_lines)


def _trim_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _list_functions_with_lines(lines: list[str], max_items: int = 40) -> list[str]:
    items: list[str] = []
    for index, line in enumerate(lines, start=1):
        for pattern in FUNCTION_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            items.append(f"{match.group(1)} @ 第 {index} 行")
            break
        if len(items) >= max_items:
            break
    return items


def _build_summary(*, parameter_name: str, parameter_type: str, reversibility: str, llm_summary: str | None) -> str:
    if llm_summary:
        return llm_summary
    return f'大模型已完成对“{parameter_name}”（{parameter_type}）相关源码的整体分析。当前判断：{_reversibility_text(reversibility)}。'


def _merge_unique(primary: list[str], secondary: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in [*primary, *secondary]:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _notify_progress(progress_callback, progress: int, step: str) -> None:
    if progress_callback is None:
        return
    progress_callback(progress, step)


def _llm_self_review_reasons(llm_insight) -> list[str]:
    reasons: list[str] = []
    reversibility = llm_insight.reversibility or "uncertain"
    key_material = dict(llm_insight.key_material)
    operations = set(llm_insight.inferred_operations)
    is_reversible = reversibility in {"potentially-reversible-encryption", "reversible-transform"}
    has_aes = "aes" in operations or any(key.startswith("aes_") for key in key_material)
    reversible_python_ops = {"base64", "urlencode", "json", "hex"}

    if operations and operations <= reversible_python_ops and llm_insight.preferred_script_type not in {None, "pure-python"}:
        reasons.append("当前操作链仅包含 Python 可直接逆向的可逆步骤，请重新确认是否应输出 pure-python。")

    if operations and operations <= reversible_python_ops and reversibility not in {"reversible-transform"}:
        reasons.append("当前操作链看起来属于可逆编码或变换，请重新确认 reversibility 是否应为 reversible-transform。")

    if not has_aes:
        return reasons

    if is_reversible and llm_insight.preferred_script_type not in {None, "pure-python"}:
        reasons.append("当前判断为可逆链路，但脚本类型不是 pure-python，请重新核对是否存在误判。")

    if is_reversible and not _valid_aes_key_length(key_material.get("aes_key")):
        reasons.append("请确认返回的 AES key 是否为最终参与运算的值，并检查其字节长度是否合法。")

    if (
        is_reversible
        and (key_material.get("aes_mode") or "CBC").upper() == "CBC"
        and not _valid_aes_iv_length(key_material.get("aes_iv"))
    ):
        reasons.append("请确认返回的 AES IV 是否为最终参与运算的值，并检查 CBC 模式下长度是否为 16 字节。")

    if is_reversible and not llm_insight.function_chain:
        reasons.append("请补充真实函数调用链，便于验证可逆流程是否完整。")

    return reasons


def _llm_python_decryptability_conflict_reasons(llm_insight) -> list[str]:
    reasons: list[str] = []
    reversibility = llm_insight.reversibility or "uncertain"
    if reversibility not in {"potentially-reversible-encryption", "reversible-transform"}:
        return reasons
    if llm_insight.preferred_script_type != "pure-python":
        return reasons

    operations = set(llm_insight.inferred_operations)
    key_material = dict(llm_insight.key_material)
    has_aes = "aes" in operations or any(key.startswith("aes_") for key in key_material)
    if not has_aes:
        return reasons

    if not _valid_aes_key_length(key_material.get("aes_key")):
        reasons.append("上一轮仍未返回合法长度的最终 AES key。")

    if (key_material.get("aes_mode") or "CBC").upper() == "CBC" and not _valid_aes_iv_length(key_material.get("aes_iv")):
        reasons.append("上一轮仍未返回合法长度的最终 AES IV。")

    if not key_material.get("aes_mode"):
        reasons.append("上一轮仍未明确返回最终 AES 模式。")

    if not key_material.get("output"):
        reasons.append("上一轮仍未明确返回最终输出编码。")

    return reasons


def _llm_self_review_enabled(llm_config) -> bool:
    value = getattr(llm_config, "self_review_enabled", None)
    if value is None:
        return True
    return bool(value)


def _valid_aes_key_length(value: str | None) -> bool:
    if not value:
        return False
    return len(value.encode("utf-8")) in {16, 24, 32}


def _valid_aes_iv_length(value: str | None) -> bool:
    if not value:
        return False
    return len(value.encode("utf-8")) == 16


def _reversibility_text(value: str) -> str:
    return {
        "potentially-reversible-encryption": "疑似可逆加密",
        "irreversible-signature-or-digest": "不可逆签名或摘要",
        "reversible-transform": "可逆编码或变换",
        "likely-irreversible-signature-or-token": "疑似不可逆签名或令牌",
        "uncertain": "暂不确定",
    }.get(value, value)
