from __future__ import annotations

import ast
import asyncio
import json
import re
import time
from contextlib import asynccontextmanager

import httpx

from app.config import (
    DEEPSEEK_REASONER_DEFAULT_MAX_TOKENS,
    GLM_DEFAULT_MAX_TOKENS,
    HTTP_RETRY_ATTEMPTS,
    HTTP_RETRY_BASE_SECONDS,
    HTTP_TIMEOUT_SECONDS,
    LLM_DEFAULT_MAX_TOKENS,
    LLM_MAX_CONCURRENT_REQUESTS,
    LLM_MAX_CONCURRENT_REQUESTS_LIMIT,
    LLM_MAX_TOKENS_LIMIT,
    LLM_MIN_MAX_TOKENS,
)
from app.models import LLMConfig, LLMInsight


DEFAULT_SYSTEM_PROMPT = """
你是一名资深 JavaScript 逆向安全工程师，仅服务于授权安全测试场景。
你的任务是分析可能经过压缩、混淆或拆包的 JavaScript，判断指定请求参数的真实生成流程，并在证据充分时提取最终参与运算的关键材料。

你必须严格遵守以下规则：
1. 所有输出必须使用简体中文。
2. 你必须基于代码证据回答，禁止猜测、补全、脑补。
3. 遇到 AES、DES、RSA、HMAC、摘要、Base64、Hex、URL 编码等流程时，必须区分：
   - 原始种子
   - 派生中间值
   - 最终参与算法运算的值
4. 如果代码存在 repeat、slice、substr、parse、Utf8.parse、derive、pad、truncate、拼接、补位等逻辑，你必须输出处理完成后的最终 key 和 iv，而不是原始字符串。
5. 只要你输出 AES key 或 AES iv，就必须同时校验其字节长度是否合法：
   - AES key 长度只能是 16/24/32 字节
   - CBC 模式下 iv 必须是 16 字节
6. 如果长度不合法，说明你提取的值不是最终值，必须继续回溯派生逻辑，不能直接输出。
7. 如果最终值仍无法确认，必须明确写“无法确认最终 key/iv”，并降级结论，禁止伪造。
8. 只有当可逆性、关键材料、模式、输出编码都明确时，才允许判断为 pure-python 可复现。
9. 所有函数链、操作链、关键材料都必须来自代码证据。
10. 最终输出必须严格符合要求的 JSON 结构，不要输出 Markdown，不要输出解释性前言。
""".strip()

DEFAULT_OPERATOR_PROMPT = """
先明确本次分析目标参数、参数位置和业务语义，再通读用户提供的全部 JS 文件，之后再判断具体加密链路。
优先分析与目标参数名、接口上下文和请求构造直接相关的代码路径。
如果代码经过混淆，请结合调用链、请求组装、加密标记、附近常量和函数职责来推断真实意图。
不要只因为某个字符串表或常量数组中出现了参数名，就把它误判为真实加密函数；必须继续追踪到真正执行加密、密钥派生、请求组装的函数。
如果参数属于 sign、token、hash 这类字段，除非证据明确表明其使用了可逆密码算法，否则不要把它描述为“可解密”。
如果识别出 AES，请不要直接输出源码里第一次出现的 key 或 iv 字符串。
你必须继续追踪其是否经过 repeat、slice、truncate、parse、Utf8.parse、拼接、补位、derive 等处理。
只有最终实际参与 CryptoJS.AES.encrypt / CryptoJS.AES.decrypt / AES.encrypt / AES.decrypt 运算的值，才允许写入 key_material.aes_key 和 key_material.aes_iv。
如果你输出了 aes_key 或 aes_iv，必须同时输出其字节长度到 aes_key_bytes 和 aes_iv_bytes。
如果字节长度不合法，说明你提取错误，必须继续回溯派生逻辑，不能直接结束。
如果链路中存在帮助复现或解密的关键材料，例如 AES key、AES iv、HMAC secret、RSA publicKey，请优先提取到 `key_material` 字段。
如果识别出的流程仅包含 Python 可直接实现的可逆步骤，例如 Base64、Hex、URL 编码、JSON 或 AES，请优先将 `preferred_script_type` 设为 `pure-python`，并保持 `reversibility` 为可逆类型。
请尽量输出真实的函数链到 `function_chain` 字段，例如 `submitLogin -> buildPayload -> encryptPassword`。
输出必须足够结构化，能够直接用于生成复现脚本与结果展示。
""".strip()

ALLOWED_REVERSIBILITY = {
    "potentially-reversible-encryption",
    "irreversible-signature-or-digest",
    "reversible-transform",
    "likely-irreversible-signature-or-token",
    "uncertain",
}
ALLOWED_SCRIPT_TYPES = {"pure-python", "report-only"}
ALLOWED_OPERATIONS = {
    "json",
    "urlencode",
    "base64",
    "hex",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "hmac",
    "aes",
    "rsa",
}


class LLMAnalysisError(RuntimeError):
    def __init__(self, message: str, *, raw_message: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.raw_message = raw_message or message

class DynamicLLMLimiter:
    def __init__(self, initial_limit: int) -> None:
        self._limit = initial_limit
        self._active = 0
        self._condition = asyncio.Condition()

    async def acquire(self, limit: int) -> None:
        normalized_limit = _normalize_concurrency_limit(limit)
        async with self._condition:
            self._limit = normalized_limit
            await self._condition.wait_for(lambda: self._active < self._limit)
            self._active += 1

    async def release(self) -> None:
        async with self._condition:
            if self._active > 0:
                self._active -= 1
            self._condition.notify_all()


LLM_REQUEST_LIMITER = DynamicLLMLimiter(LLM_MAX_CONCURRENT_REQUESTS)


def validate_llm_config(llm_config: LLMConfig) -> tuple[str, str]:
    missing = []
    if not llm_config.base_url:
        missing.append("接口地址")
    if not llm_config.model_name:
        missing.append("模型名称")
    if not llm_config.api_key:
        missing.append("接口密钥")
    if missing:
        raise LLMAnalysisError(f"必须先完整配置大模型。缺少：{', '.join(missing)}。")
    system_prompt = (llm_config.system_prompt or DEFAULT_SYSTEM_PROMPT).strip()
    operator_prompt = (llm_config.operator_prompt or DEFAULT_OPERATOR_PROMPT).strip()
    system_prompt = f"{system_prompt}\n\n硬性要求：所有自然语言输出必须使用简体中文。"
    return system_prompt, operator_prompt


async def analyze_with_llm(
    *,
    llm_config: LLMConfig,
    parameter_name: str,
    parameter_type: str,
    parameter_location: str,
    parameter_hint: str | None,
    api_context: str | None,
    webpage_url: str | None,
    validation_plaintext: str | None,
    validation_ciphertext: str | None,
    source_summaries: list[dict],
    context_blocks: list[dict],
    analysis_overview: dict | None = None,
    debug_writer=None,
) -> LLMInsight:
    system_prompt, operator_prompt = validate_llm_config(llm_config)

    prompt = _build_prompt(
        parameter_name=parameter_name,
        parameter_type=parameter_type,
        parameter_location=parameter_location,
        parameter_hint=parameter_hint,
        api_context=api_context,
        webpage_url=webpage_url,
        validation_plaintext=validation_plaintext,
        validation_ciphertext=validation_ciphertext,
        source_summaries=source_summaries,
        context_blocks=context_blocks,
        analysis_overview=analysis_overview,
    )
    parsed, content = await _invoke_llm_json(
        llm_config=llm_config,
        system_prompt=system_prompt,
        operator_prompt=operator_prompt,
        prompt=prompt,
        stage="analysis",
        debug_writer=debug_writer,
    )
    return _build_llm_insight(
        llm_config=llm_config,
        system_prompt=system_prompt,
        operator_prompt=operator_prompt,
        parsed=parsed,
        content=content,
    )


async def answer_followup_with_llm(
    *,
    llm_config: LLMConfig,
    session_payload: dict,
    user_question: str,
    debug_writer=None,
) -> str:
    system_prompt, operator_prompt = validate_llm_config(llm_config)
    followup_system_prompt = (
        f"{system_prompt}\n\n"
        "当前不是重新跑整套 JS 静态分析，而是基于已经完成的分析会话继续回答追问。"
        "你必须优先使用会话摘要、关键函数片段、关键材料和已有结论来回答。"
        "如果现有会话材料不足以支持确定答案，必须明确说明不足点，禁止编造。"
        "所有回答必须使用简体中文。"
    )
    followup_prompt = _build_followup_prompt(
        operator_prompt=operator_prompt,
        session_payload=session_payload,
        user_question=user_question,
    )
    return await _invoke_llm_text(
        llm_config=llm_config,
        system_prompt=followup_system_prompt,
        prompt=followup_prompt,
        stage="followup",
        debug_writer=debug_writer,
    )


async def survey_with_llm(
    *,
    llm_config: LLMConfig,
    parameter_name: str,
    parameter_type: str,
    parameter_location: str,
    parameter_hint: str | None,
    api_context: str | None,
    webpage_url: str | None,
    source_summaries: list[dict],
    context_blocks: list[dict],
    debug_writer=None,
) -> dict:
    system_prompt, operator_prompt = validate_llm_config(llm_config)
    survey_operator_prompt = (
        f"{operator_prompt}\n\n"
        "当前是第一阶段全量通读，请先建立对全部源码的整体理解，再返回后续精读所需的聚焦线索。"
        "这一阶段不要急于给出最终加密结论，也不要生成脚本结论。"
        "你的主要任务是：识别相关文件、真实函数链、密钥派生位置、请求组装位置，并给出下一阶段应重点精读的源码定位。"
        "这一阶段不要返回 JSON，请按固定中文小节输出，便于后端继续整理。"
    )
    prompt = _build_survey_prompt(
        parameter_name=parameter_name,
        parameter_type=parameter_type,
        parameter_location=parameter_location,
        parameter_hint=parameter_hint,
        api_context=api_context,
        webpage_url=webpage_url,
        source_summaries=source_summaries,
        context_blocks=context_blocks,
    )
    content = await _invoke_llm_text(
        llm_config=llm_config,
        system_prompt=system_prompt,
        prompt=f"{survey_operator_prompt}\n\n{prompt}",
        stage="survey",
        debug_writer=debug_writer,
    )
    parsed = _parse_survey_text_result(content)
    if _survey_result_has_signal(parsed):
        normalized = _normalize_survey_result(parsed)
        _write_debug(debug_writer, stage="survey", name="parsed_result", payload=normalized)
        return normalized

    fallback_json = _extract_json_object(content)
    if fallback_json is not None:
        normalized = _normalize_survey_result(fallback_json)
        _write_debug(debug_writer, stage="survey", name="parsed_result", payload=normalized)
        return normalized

    raise LLMAnalysisError(
        "第一阶段全量通读结果无法整理为聚焦线索。"
        f" 原始输出片段：{_trim_excerpt(content)}"
    )


async def review_with_llm(
    *,
    llm_config: LLMConfig,
    parameter_name: str,
    parameter_type: str,
    parameter_location: str,
    parameter_hint: str | None,
    api_context: str | None,
    webpage_url: str | None,
    source_summaries: list[dict],
    context_blocks: list[dict],
    initial_insight: LLMInsight,
    audit_reasons: list[str],
    debug_writer=None,
) -> LLMInsight:
    system_prompt, operator_prompt = validate_llm_config(llm_config)
    review_operator_prompt = (
        f"{operator_prompt}\n\n"
        "现在请对上一轮结构化分析结果执行严格自审查。"
        "请先重新整理代码事实，再根据事实修正操作链、函数链、关键材料和最终结论。"
        "如果你发现上一轮结果与源码不一致，必须直接纠正，而不是沿用旧答案。"
        "如果源码中存在长度扩展、重复、截断、派生、parse、编码、摘要、签名或自定义字符串变换逻辑，请输出最终参与运算的真实值或明确承认无法确认。"
        "如果无法确认，请明确降级为 uncertain 或 report-only。"
    )
    prompt = _build_review_prompt(
        parameter_name=parameter_name,
        parameter_type=parameter_type,
        parameter_location=parameter_location,
        parameter_hint=parameter_hint,
        api_context=api_context,
        webpage_url=webpage_url,
        source_summaries=source_summaries,
        context_blocks=context_blocks,
        initial_insight=initial_insight,
        audit_reasons=audit_reasons,
    )
    parsed, content = await _invoke_llm_json(
        llm_config=llm_config,
        system_prompt=system_prompt,
        operator_prompt=review_operator_prompt,
        prompt=prompt,
        stage="review",
        debug_writer=debug_writer,
    )
    reviewed = _build_llm_insight(
        llm_config=llm_config,
        system_prompt=system_prompt,
        operator_prompt=review_operator_prompt,
        parsed=parsed,
        content=content,
    )
    reviewed.warnings = [*reviewed.warnings, "本次结果已触发模型自审查复核。"]
    return reviewed


async def resolve_python_decryptability_with_llm(
    *,
    llm_config: LLMConfig,
    parameter_name: str,
    parameter_type: str,
    parameter_location: str,
    parameter_hint: str | None,
    api_context: str | None,
    webpage_url: str | None,
    source_summaries: list[dict],
    context_blocks: list[dict],
    initial_insight: LLMInsight,
    audit_reasons: list[str],
    debug_writer=None,
) -> LLMInsight:
    system_prompt, operator_prompt = validate_llm_config(llm_config)
    review_operator_prompt = (
        f"{operator_prompt}\n\n"
        "现在请执行第三轮关键材料一致性复核。"
        "当前已知上一轮结果中的直接事实和最终结论仍有冲突。"
        "你必须优先解决关键材料、操作链、函数链与脚本类型之间的矛盾。"
        "如果最终参与运算的关键材料仍无法确认，请不要继续保留 pure-python，必须改为 report-only，必要时把 reversibility 降为 uncertain。"
        "禁止为了维持既有结论而补推并不存在的事实。"
    )
    prompt = _build_conflict_resolution_prompt(
        parameter_name=parameter_name,
        parameter_type=parameter_type,
        parameter_location=parameter_location,
        parameter_hint=parameter_hint,
        api_context=api_context,
        webpage_url=webpage_url,
        source_summaries=source_summaries,
        context_blocks=context_blocks,
        initial_insight=initial_insight,
        audit_reasons=audit_reasons,
    )
    parsed, content = await _invoke_llm_json(
        llm_config=llm_config,
        system_prompt=system_prompt,
        operator_prompt=review_operator_prompt,
        prompt=prompt,
        stage="conflict",
        debug_writer=debug_writer,
    )
    reviewed = _build_llm_insight(
        llm_config=llm_config,
        system_prompt=system_prompt,
        operator_prompt=review_operator_prompt,
        parsed=parsed,
        content=content,
    )
    reviewed.warnings = [*reviewed.warnings, "本次结果已触发第三轮关键材料一致性复核。"]
    return reviewed


async def _invoke_llm_json(
    *,
    llm_config: LLMConfig,
    system_prompt: str,
    operator_prompt: str,
    prompt: str,
    stage: str,
    debug_writer=None,
) -> tuple[dict, str]:
    endpoint = _normalize_endpoint(llm_config.base_url or "")
    payload = _build_payload(
        endpoint=endpoint,
        llm_config=llm_config,
        system_prompt=system_prompt,
        user_prompt=f"{operator_prompt}\n\n{prompt}",
        stage=stage,
        expect_json=True,
    )
    headers = {
        "Authorization": f"Bearer {llm_config.api_key}",
        "Content-Type": "application/json",
    }
    _write_debug(
        debug_writer,
        stage=stage,
        name="prepared_request",
        payload={
            "endpoint": endpoint,
            "payload": payload,
        },
    )
    try:
        data = await _request_completion(
            endpoint=endpoint,
            headers=headers,
            payload=payload,
            llm_config=llm_config,
            stage=stage,
            debug_writer=debug_writer,
        )
    except LLMAnalysisError:
        raise
    except Exception as exc:
        raise LLMAnalysisError(f"请求大模型失败：{exc}") from exc

    message = data.get("choices", [{}])[0].get("message", {})
    content = _extract_message_content(message)
    parsed = _extract_json_object(content)
    glm_thinking_enabled = _glm_thinking_payload_enabled(payload)
    if parsed is None and glm_thinking_enabled and _should_retry_glm_without_thinking(
        data=data,
        endpoint=endpoint,
        llm_config=llm_config,
        expect_json=True,
    ):
        retry_payload = _build_glm_no_thinking_payload(payload)
        _write_debug(
            debug_writer,
            stage=stage,
            name="semantic_retry_reason",
            payload=_glm_retry_diagnostics(data, reason="thinking 返回了空正文或截断结果，改为关闭 thinking 重试"),
        )
        try:
            data = await _request_completion(
                endpoint=endpoint,
                headers=headers,
                payload=retry_payload,
                llm_config=llm_config,
                stage=stage,
                debug_writer=debug_writer,
            )
        except LLMAnalysisError:
            raise
        except Exception as exc:
            raise LLMAnalysisError(f"请求大模型失败：{exc}") from exc
        message = data.get("choices", [{}])[0].get("message", {})
        content = _extract_message_content(message)
        parsed = _extract_json_object(content)
    if parsed is None:
        raise LLMAnalysisError(
            "大模型返回内容无法解析为 JSON，请检查提示词或模型兼容性。"
            f" 原始输出片段：{_trim_excerpt(content)}"
            f"{_glm_empty_content_hint(data=data, endpoint=endpoint, llm_config=llm_config, expect_json=True)}"
        )
    return parsed, content


async def _invoke_llm_text(
    *,
    llm_config: LLMConfig,
    system_prompt: str,
    prompt: str,
    stage: str,
    debug_writer=None,
) -> str:
    endpoint = _normalize_endpoint(llm_config.base_url or "")
    payload = _build_payload(
        endpoint=endpoint,
        llm_config=llm_config,
        system_prompt=system_prompt,
        user_prompt=prompt,
        stage=stage,
        expect_json=False,
    )
    headers = {
        "Authorization": f"Bearer {llm_config.api_key}",
        "Content-Type": "application/json",
    }
    _write_debug(
        debug_writer,
        stage=stage,
        name="prepared_request",
        payload={
            "endpoint": endpoint,
            "payload": payload,
        },
    )
    try:
        data = await _request_completion(
            endpoint=endpoint,
            headers=headers,
            payload=payload,
            llm_config=llm_config,
            stage=stage,
            debug_writer=debug_writer,
        )
    except LLMAnalysisError:
        raise
    except Exception as exc:
        raise LLMAnalysisError(f"请求大模型失败：{exc}") from exc

    message = data.get("choices", [{}])[0].get("message", {})
    content = _extract_message_content(message).strip()
    glm_thinking_enabled = _glm_thinking_payload_enabled(payload)
    if not content and glm_thinking_enabled and _should_retry_glm_without_thinking(
        data=data,
        endpoint=endpoint,
        llm_config=llm_config,
        expect_json=False,
    ):
        retry_payload = _build_glm_no_thinking_payload(payload)
        _write_debug(
            debug_writer,
            stage=stage,
            name="semantic_retry_reason",
            payload=_glm_retry_diagnostics(data, reason="thinking 返回了空正文，改为关闭 thinking 重试"),
        )
        try:
            data = await _request_completion(
                endpoint=endpoint,
                headers=headers,
                payload=retry_payload,
                llm_config=llm_config,
                stage=stage,
                debug_writer=debug_writer,
            )
        except LLMAnalysisError:
            raise
        except Exception as exc:
            raise LLMAnalysisError(f"请求大模型失败：{exc}") from exc
        message = data.get("choices", [{}])[0].get("message", {})
        content = _extract_message_content(message).strip()
    if not content:
        empty_message = "大模型没有返回可用的追问回答内容。" if stage == "followup" else "大模型没有返回可用文本内容。"
        raise LLMAnalysisError(
            empty_message +
            f"{_glm_empty_content_hint(data=data, endpoint=endpoint, llm_config=llm_config, expect_json=False)}"
        )
    return content


def _build_llm_insight(
    *,
    llm_config: LLMConfig,
    system_prompt: str,
    operator_prompt: str,
    parsed: dict,
    content: str,
) -> LLMInsight:
    warnings = _as_string_list(parsed.get("warnings"))
    reversibility = _normalize_reversibility(parsed.get("reversibility"))
    confidence = _normalize_confidence(parsed.get("confidence"))
    preferred_script_type = _normalize_script_type(parsed.get("preferred_script_type"))
    inferred_operations = _normalize_operations(parsed.get("inferred_operations"))
    key_material = _normalize_key_material(parsed.get("key_material"))

    return LLMInsight(
        used=True,
        provider=llm_config.provider_name,
        model=llm_config.model_name,
        system_prompt=system_prompt,
        operator_prompt=operator_prompt,
        summary=_optional_string(parsed.get("summary")),
        reversibility=reversibility,
        confidence=confidence,
        flow_steps=_as_string_list(parsed.get("flow_steps")),
        warnings=warnings,
        inferred_operations=inferred_operations,
        function_chain=_normalize_function_chain(parsed.get("function_chain")),
        preferred_script_type=preferred_script_type,
        selected_candidates=_as_string_list(parsed.get("selected_candidates")),
        observed_facts=_normalize_observed_facts(parsed.get("observed_facts")),
        reasoning_notes=_as_string_list(parsed.get("reasoning_notes")),
        key_material=key_material,
        raw_excerpt=content[:2000],
    )


async def _request_completion(
    *,
    endpoint: str,
    headers: dict[str, str],
    payload: dict,
    llm_config: LLMConfig,
    stage: str,
    debug_writer=None,
) -> dict:
    async with _llm_request_slot(llm_config.max_concurrency):
        async with httpx.AsyncClient(timeout=_request_timeout_seconds(llm_config), follow_redirects=True) as client:
            for attempt in range(1, HTTP_RETRY_ATTEMPTS + 1):
                started_at = time.perf_counter()
                try:
                    data = await _post_with_fallback(
                        client=client,
                        endpoint=endpoint,
                        headers=headers,
                        payload=payload,
                        llm_config=llm_config,
                        stage=stage,
                        attempt=attempt,
                        debug_writer=debug_writer,
                    )
                    _write_debug(
                        debug_writer,
                        stage=stage,
                        name=f"attempt_{attempt}_meta",
                        payload={
                            "attempt": attempt,
                            "status": "ok",
                            "duration_seconds": round(time.perf_counter() - started_at, 3),
                        },
                    )
                    return data
                except httpx.HTTPStatusError as exc:
                    status_code = exc.response.status_code
                    _write_debug(
                        debug_writer,
                        stage=stage,
                        name=f"attempt_{attempt}_http_error",
                        payload={
                            "attempt": attempt,
                            "status_code": status_code,
                            "duration_seconds": round(time.perf_counter() - started_at, 3),
                            "detail": _extract_error_detail(exc.response),
                            "response_text": _extract_raw_response_text(exc.response),
                        },
                    )
                    if status_code == 429:
                        wait_seconds = _rate_limit_wait_seconds(exc.response, attempt)
                        if attempt < HTTP_RETRY_ATTEMPTS:
                            await asyncio.sleep(wait_seconds)
                            continue
                        raise LLMAnalysisError(
                            _format_rate_limit_error(exc.response, wait_seconds, attempt),
                            raw_message=_format_original_http_error(exc),
                        ) from exc
                    if status_code in {408, 500, 502, 503, 504} and attempt < HTTP_RETRY_ATTEMPTS:
                        await asyncio.sleep(_retry_backoff_seconds(attempt))
                        continue
                    raise LLMAnalysisError(
                        _format_http_error(exc.response),
                        raw_message=_format_original_http_error(exc),
                    ) from exc
                except httpx.TimeoutException as exc:
                    _write_debug(
                        debug_writer,
                        stage=stage,
                        name=f"attempt_{attempt}_timeout",
                        payload={
                            "attempt": attempt,
                            "duration_seconds": round(time.perf_counter() - started_at, 3),
                            "error": str(exc),
                        },
                    )
                    if attempt < HTTP_RETRY_ATTEMPTS:
                        await asyncio.sleep(_retry_backoff_seconds(attempt))
                        continue
                    raise LLMAnalysisError(
                        f"请求大模型超时，已自动重试 {attempt} 次仍失败。请稍后重试，或检查模型接口响应速度。",
                        raw_message=str(exc),
                    ) from exc
                except httpx.RequestError as exc:
                    _write_debug(
                        debug_writer,
                        stage=stage,
                        name=f"attempt_{attempt}_request_error",
                        payload={
                            "attempt": attempt,
                            "duration_seconds": round(time.perf_counter() - started_at, 3),
                            "error": str(exc),
                        },
                    )
                    raise LLMAnalysisError(f"无法连接到大模型接口：{exc}", raw_message=str(exc)) from exc
    raise LLMAnalysisError("请求大模型失败：未获得有效响应。")


@asynccontextmanager
async def _llm_request_slot(limit: int | None):
    await LLM_REQUEST_LIMITER.acquire(limit or LLM_MAX_CONCURRENT_REQUESTS)
    try:
        yield
    finally:
        await LLM_REQUEST_LIMITER.release()


async def _post_with_fallback(
    *,
    client: httpx.AsyncClient,
    endpoint: str,
    headers: dict[str, str],
    payload: dict,
    llm_config: LLMConfig,
    stage: str,
    attempt: int,
    debug_writer=None,
) -> dict:
    payload_variants = _payload_variants(payload, endpoint=endpoint, llm_config=llm_config)
    last_exc: httpx.HTTPStatusError | None = None
    for variant_index, variant in enumerate(payload_variants, start=1):
        _write_debug(
            debug_writer,
            stage=stage,
            name=f"attempt_{attempt}_variant_{variant_index}_request",
            payload={
                "endpoint": endpoint,
                "payload": variant,
            },
        )
        try:
            response = await client.post(endpoint, headers=headers, json=variant)
            response.raise_for_status()
            data = response.json()
            _write_debug(
                debug_writer,
                stage=stage,
                name=f"attempt_{attempt}_variant_{variant_index}_response",
                payload=data,
            )
            return data
        except httpx.HTTPStatusError as exc:
            last_exc = exc
            status_code = exc.response.status_code
            _write_debug(
                debug_writer,
                stage=stage,
                name=f"attempt_{attempt}_variant_{variant_index}_response_error",
                payload={
                    "status_code": status_code,
                    "detail": _extract_error_detail(exc.response),
                    "response_text": _extract_raw_response_text(exc.response),
                },
            )
            if status_code not in {400, 404, 415, 422}:
                raise
            continue
    if last_exc is not None:
        raise last_exc
    raise LLMAnalysisError("请求大模型失败：未获得有效响应。")


def _build_survey_prompt(
    *,
    parameter_name: str,
    parameter_type: str,
    parameter_location: str,
    parameter_hint: str | None,
    api_context: str | None,
    webpage_url: str | None,
    source_summaries: list[dict],
    context_blocks: list[dict],
) -> str:
    parameter_payload = {
        "name": parameter_name,
        "type": parameter_type,
        "location": parameter_location,
        "hint": parameter_hint,
        "api_context": api_context,
        "webpage_url": webpage_url,
    }
    return "\n".join(
        [
            "第一阶段任务：请先完整理解全部 JavaScript 源码，再提炼后续精读所需的聚焦线索。",
            "输出要求：不要返回 JSON，不要 Markdown，不要解释输出格式。",
            "请严格按下面的小节顺序输出：",
            "全局摘要：<一句到三句中文总结>",
            "相关文件：",
            "- <文件名>",
            "重点目标：",
            "- file=<文件名> | line=<行号或留空> | function=<函数名或留空> | reason=<为什么值得第二阶段精读>",
            "疑似函数链：",
            "- <函数名>",
            "疑似操作：",
            f"- <从 {', '.join(sorted(ALLOWED_OPERATIONS))} 中选择最相关项>",
            "备注：",
            "- <后续精读时要重点核对的简短备注>",
            "",
            f"参数信息：{json.dumps(parameter_payload, ensure_ascii=False, separators=(',', ':'))}",
            f"源码摘要：{json.dumps(source_summaries, ensure_ascii=False, separators=(',', ':'))}",
            f"源码上下文：{json.dumps(context_blocks, ensure_ascii=False, separators=(',', ':'))}",
        ]
    )


def _build_followup_prompt(
    *,
    operator_prompt: str,
    session_payload: dict,
    user_question: str,
) -> str:
    return json.dumps(
        {
            "task": "请基于已有分析会话回答新的追问，不要把它当成重新上传整套 JS 的首次分析。",
            "operator_prompt": operator_prompt,
            "response_requirement": [
                "先结合现有会话摘要和关键片段回答问题。",
                "如果问题和现有材料直接相关，请尽量给出明确结论。",
                "如果材料不足，请指出具体缺口，例如缺少哪段函数体、哪一步派生证据不足。",
                "不要编造不存在的 key、iv、函数链或算法步骤。",
            ],
            "session_payload": session_payload,
            "user_question": user_question,
        },
        ensure_ascii=False,
        indent=2,
    )


def _fact_priority_rules() -> list[str]:
    return [
        "先提取代码事实，再根据事实归纳操作链和函数链，最后再判断可逆性、脚本类型和总结。",
        "observed_facts 只能写代码中直接出现或可由简单确定性变换得到的事实，例如字面量、常量数组、函数调用、参数传递、模式、输出形式、长度处理、固定种子或固定密钥来源。",
        "不要把经验判断、库默认值、常见实现习惯或猜测写进 observed_facts。",
        "如果事实不足以支撑结论，保留事实并降低 confidence，必要时把 reversibility 设为 uncertain、preferred_script_type 设为 report-only。",
        "这一原则适用于 AES、DES、RSA、HMAC、摘要、Base64、Hex、URL 编码、JSON、压缩、自定义位运算和字符串混淆，不局限于某一种算法。",
    ]


def _structured_output_schema() -> dict:
    return {
        "observed_facts": ["直接代码事实"],
        "summary": "中文总结",
        "reversibility": list(ALLOWED_REVERSIBILITY),
        "confidence": "0.0-1.0",
        "flow_steps": ["中文步骤"],
        "warnings": ["中文警告"],
        "inferred_operations": list(ALLOWED_OPERATIONS),
        "function_chain": ["函数名"],
        "preferred_script_type": list(ALLOWED_SCRIPT_TYPES),
        "selected_candidates": ["file.js:120"],
        "reasoning_notes": ["简短证据说明"],
        "key_material": {
            "seed_key": "字符串",
            "seed_iv": "字符串",
            "derivation_steps": ["步骤"],
            "secret": "字符串",
            "aes_key": "字符串",
            "aes_key_bytes": "整数",
            "aes_iv": "字符串",
            "aes_iv_bytes": "整数",
            "aes_mode": "CBC|ECB",
            "output": "base64|hex",
        },
    }


def _structured_output_template() -> dict:
    return {
        "observed_facts": [],
        "summary": "",
        "reversibility": "uncertain",
        "confidence": 0.0,
        "flow_steps": [],
        "warnings": [],
        "inferred_operations": [],
        "function_chain": [],
        "preferred_script_type": "report-only",
        "selected_candidates": [],
        "reasoning_notes": [],
        "key_material": {
            "seed_key": "",
            "seed_iv": "",
            "derivation_steps": [],
            "secret": "",
            "aes_key": "",
            "aes_key_bytes": 0,
            "aes_iv": "",
            "aes_iv_bytes": 0,
            "aes_mode": "",
            "output": "",
        },
    }


def _build_prompt(
    *,
    parameter_name: str,
    parameter_type: str,
    parameter_location: str,
    parameter_hint: str | None,
    api_context: str | None,
    webpage_url: str | None,
    validation_plaintext: str | None,
    validation_ciphertext: str | None,
    source_summaries: list[dict],
    context_blocks: list[dict],
    analysis_overview: dict | None,
) -> str:
    return json.dumps(
        {
            "task": "第二阶段：基于第一阶段的全量通读结果和重点源码片段，先提取代码事实，再输出最终参数分析结论。",
            "workflow_requirement": [
                "先参考第一阶段结论，但不要把 analysis_overview 当成事实本身，必须再次以当前代码片段为准。",
                "先填写 observed_facts，再填写 inferred_operations、function_chain、key_material，最后再填写 reversibility、preferred_script_type、summary。",
                "如果某个字段仍不确定，请明确留空或降级，不要编造。",
                "如果 key_material、函数链和最终结论发生冲突，优先保留事实并降低结论，不要强行维持 pure-python。",
            ],
            "fact_priority_rules": _fact_priority_rules(),
            "parameter": {
                "name": parameter_name,
                "type": parameter_type,
                "location": parameter_location,
                "hint": parameter_hint,
                "api_context": api_context,
                "webpage_url": webpage_url,
            },
            "validation_pair": {
                "plaintext": validation_plaintext,
                "ciphertext": validation_ciphertext,
            },
            "analysis_overview": analysis_overview,
            "source_summaries": source_summaries,
            "focused_context_blocks": context_blocks,
            "json_rules": [
                "只返回一个 JSON 对象，不要返回 Markdown，不要返回前言。",
                "unknown 字段用空字符串、空数组或 uncertain/report-only 表示。",
                "observed_facts 只写直接事实，不写推断和评价。",
            ],
            "output_schema": _structured_output_schema(),
            "output_template": _structured_output_template(),
        },
        ensure_ascii=False,
        indent=2,
    )


def _build_review_prompt(
    *,
    parameter_name: str,
    parameter_type: str,
    parameter_location: str,
    parameter_hint: str | None,
    api_context: str | None,
    webpage_url: str | None,
    source_summaries: list[dict],
    context_blocks: list[dict],
    initial_insight: LLMInsight,
    audit_reasons: list[str],
) -> str:
    return json.dumps(
        {
            "task": "请对上一轮 JavaScript 参数分析结果执行自审查，并按事实优先原则纠正结论。",
            "review_focus": [
                "不要默认上一轮输出正确，必须重新核对源码证据。",
                "先重新判断 previous_result 中哪些字段属于直接事实，哪些字段只是推断结论。",
                "优先修正 observed_facts、function_chain、inferred_operations、key_material，再决定 reversibility、summary 和 preferred_script_type。",
                "如果事实不足以支撑上一轮结论，请直接降级，不要为了维持旧结论而补推事实。",
                "如果输出了加解密关键材料，必须再次确认它们是最终参与运算的值，而不是中间种子或猜测值。",
            ],
            "fact_priority_rules": _fact_priority_rules(),
            "parameter": {
                "name": parameter_name,
                "type": parameter_type,
                "location": parameter_location,
                "hint": parameter_hint,
                "api_context": api_context,
                "webpage_url": webpage_url,
            },
            "audit_reasons": audit_reasons,
            "previous_result": {
                "summary": initial_insight.summary,
                "reversibility": initial_insight.reversibility,
                "confidence": initial_insight.confidence,
                "flow_steps": initial_insight.flow_steps,
                "inferred_operations": initial_insight.inferred_operations,
                "function_chain": initial_insight.function_chain,
                "preferred_script_type": initial_insight.preferred_script_type,
                "observed_facts": initial_insight.observed_facts,
                "reasoning_notes": initial_insight.reasoning_notes,
                "key_material": initial_insight.key_material,
            },
            "source_summaries": source_summaries,
            "context_blocks": context_blocks,
            "json_rules": [
                "只返回一个 JSON 对象，不要返回 Markdown，不要返回前言。",
                "如果发现 previous_result 的事实字段有误，直接修正，不要只在 reasoning_notes 里说明。",
                "observed_facts 仍然只能写直接事实，不写推断和评价。",
            ],
            "output_schema": _structured_output_schema(),
            "output_template": _structured_output_template(),
        },
        ensure_ascii=False,
        indent=2,
    )


def _build_conflict_resolution_prompt(
    *,
    parameter_name: str,
    parameter_type: str,
    parameter_location: str,
    parameter_hint: str | None,
    api_context: str | None,
    webpage_url: str | None,
    source_summaries: list[dict],
    context_blocks: list[dict],
    initial_insight: LLMInsight,
    audit_reasons: list[str],
) -> str:
    return json.dumps(
        {
            "task": "请解决上一轮结果中的事实与结论冲突，并优先保留事实。",
            "resolution_focus": [
                "上一轮已经出现事实与结论冲突，请不要扩展无关推断，只解决冲突本身。",
                "先检查 observed_facts、function_chain、inferred_operations、key_material 是否真的支撑 pure-python 和可逆性判断。",
                "如果最终事实仍不足，请保留事实并把 preferred_script_type 改为 report-only，同时根据证据重新评估 reversibility。",
                "适用于加密、编码、摘要、签名、压缩、自定义字符串或位运算变换，不局限于某一种算法。",
                "如果输出了关键材料，必须保证它们是最终参与运算的值；如果无法确认，就留空。",
            ],
            "fact_priority_rules": _fact_priority_rules(),
            "parameter": {
                "name": parameter_name,
                "type": parameter_type,
                "location": parameter_location,
                "hint": parameter_hint,
                "api_context": api_context,
                "webpage_url": webpage_url,
            },
            "audit_reasons": audit_reasons,
            "previous_result": {
                "summary": initial_insight.summary,
                "reversibility": initial_insight.reversibility,
                "confidence": initial_insight.confidence,
                "flow_steps": initial_insight.flow_steps,
                "inferred_operations": initial_insight.inferred_operations,
                "function_chain": initial_insight.function_chain,
                "preferred_script_type": initial_insight.preferred_script_type,
                "observed_facts": initial_insight.observed_facts,
                "reasoning_notes": initial_insight.reasoning_notes,
                "key_material": initial_insight.key_material,
            },
            "source_summaries": source_summaries,
            "context_blocks": context_blocks,
            "json_rules": [
                "只返回一个 JSON 对象，不要返回 Markdown，不要返回前言。",
                "如果事实无法稳定支撑 pure-python，就必须降级为 report-only。",
                "observed_facts 仍然只能写直接事实，不写推断和评价。",
            ],
            "output_schema": _structured_output_schema(),
            "output_template": _structured_output_template(),
        },
        ensure_ascii=False,
        indent=2,
    )


def _normalize_endpoint(base_url: str) -> str:
    endpoint = base_url.rstrip("/")
    if endpoint.endswith("/chat/completions"):
        return endpoint
    return f"{endpoint}/chat/completions"


def _normalize_concurrency_limit(value: int | None) -> int:
    try:
        number = int(value or LLM_MAX_CONCURRENT_REQUESTS)
    except (TypeError, ValueError):
        number = LLM_MAX_CONCURRENT_REQUESTS
    return max(1, min(number, LLM_MAX_CONCURRENT_REQUESTS_LIMIT))


def _payload_variants(payload: dict, *, endpoint: str, llm_config: LLMConfig) -> list[dict]:
    variants: list[dict] = [dict(payload)]
    is_deepseek = _is_deepseek_compatible(endpoint, llm_config)
    is_glm = _is_glm_compatible(endpoint, llm_config)
    is_reasoner = "reasoner" in (llm_config.model_name or "").lower()

    if "response_format" in payload:
        no_response_format = dict(payload)
        no_response_format.pop("response_format", None)
        variants.append(no_response_format)

    if is_deepseek and is_reasoner and "temperature" in payload:
        no_temperature = dict(payload)
        no_temperature.pop("temperature", None)
        variants.append(no_temperature)
        if "response_format" in payload:
            no_both = dict(no_temperature)
            no_both.pop("response_format", None)
            variants.append(no_both)

    if is_glm and "thinking" in payload:
        no_thinking = dict(payload)
        no_thinking.pop("thinking", None)
        variants.append(no_thinking)
        if "response_format" in payload:
            no_thinking_no_response = dict(no_thinking)
            no_thinking_no_response.pop("response_format", None)
            variants.append(no_thinking_no_response)

    if is_glm and "do_sample" in payload:
        no_do_sample = dict(payload)
        no_do_sample.pop("do_sample", None)
        variants.append(no_do_sample)

    deduped: list[dict] = []
    seen: set[str] = set()
    for item in variants:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _is_deepseek_compatible(endpoint: str, llm_config: LLMConfig) -> bool:
    provider = (llm_config.provider_name or "").lower()
    model_name = (llm_config.model_name or "").lower()
    endpoint_lower = endpoint.lower()
    return "deepseek" in provider or "deepseek" in model_name or "api.deepseek.com" in endpoint_lower


def _is_glm_compatible(endpoint: str, llm_config: LLMConfig) -> bool:
    provider = (llm_config.provider_name or "").lower()
    model_name = (llm_config.model_name or "").lower()
    endpoint_lower = endpoint.lower()
    return "glm" in provider or model_name.startswith("glm") or "bigmodel.cn" in endpoint_lower


def _build_payload(
    *,
    endpoint: str,
    llm_config: LLMConfig,
    system_prompt: str,
    user_prompt: str,
    stage: str,
    expect_json: bool,
) -> dict:
    payload: dict[str, object] = {
        "model": llm_config.model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": _resolve_max_tokens(llm_config, stage=stage),
    }
    temperature = _resolve_temperature(endpoint=endpoint, llm_config=llm_config)
    if temperature is not None:
        payload["temperature"] = temperature
    if expect_json:
        payload["response_format"] = {"type": "json_object"}
    if _is_glm_compatible(endpoint, llm_config):
        payload["do_sample"] = False
        if _glm_supports_thinking(llm_config):
            payload["thinking"] = {
                "type": "enabled" if _resolve_glm_thinking_enabled(llm_config) else "disabled"
            }
    return payload


def _glm_supports_thinking(llm_config: LLMConfig) -> bool:
    model_name = (llm_config.model_name or "").lower()
    return model_name.startswith("glm-4.5") or model_name.startswith("glm-4.6") or model_name.startswith("glm-4.7") or model_name.startswith("glm-5")


def _resolve_glm_thinking_enabled(llm_config: LLMConfig) -> bool:
    if llm_config.glm_thinking_enabled is None:
        return True
    return bool(llm_config.glm_thinking_enabled)


def _glm_thinking_payload_enabled(payload: dict) -> bool:
    thinking = payload.get("thinking")
    return isinstance(thinking, dict) and str(thinking.get("type") or "").lower() == "enabled"


def _resolve_temperature(*, endpoint: str, llm_config: LLMConfig) -> float | None:
    if _is_glm_compatible(endpoint, llm_config):
        return None
    if _is_deepseek_compatible(endpoint, llm_config):
        return 0.0
    return 0.1


def _resolve_max_tokens(llm_config: LLMConfig, *, stage: str) -> int:
    configured = _normalize_max_tokens_value(llm_config.max_tokens)
    is_glm = (llm_config.provider_name or "").lower() == "glm" or (llm_config.model_name or "").lower().startswith("glm")
    if configured is None:
        if is_glm:
            configured = GLM_DEFAULT_MAX_TOKENS
        else:
            configured = DEEPSEEK_REASONER_DEFAULT_MAX_TOKENS or LLM_DEFAULT_MAX_TOKENS

    if is_glm:
        if stage == "survey":
            return max(4096, min(configured, 8192))
        if stage in {"review", "conflict"}:
            return max(4096, min(configured, 8192))
        if stage == "followup":
            return max(2048, min(configured, 4096))
        return max(8192, min(configured, 16384))

    if stage == "survey":
        return max(3072, min(configured, 6000))
    if stage in {"review", "conflict"}:
        return max(4096, min(configured, 8000))
    if stage == "followup":
        return max(1536, min(configured, 3072))
    return configured


def _build_glm_no_thinking_payload(payload: dict) -> dict:
    retry_payload = dict(payload)
    retry_payload.pop("thinking", None)
    return retry_payload


def _should_retry_glm_without_thinking(
    *,
    data: dict,
    endpoint: str,
    llm_config: LLMConfig,
    expect_json: bool,
) -> bool:
    if not _is_glm_compatible(endpoint, llm_config):
        return False
    choice = data.get("choices", [{}])[0]
    message = choice.get("message", {})
    finish_reason = str(choice.get("finish_reason") or "").strip().lower()
    content = _extract_message_content(message).strip()
    reasoning_content = _extract_reasoning_content(message).strip()
    if content:
        if expect_json and _extract_json_object(content) is None and finish_reason == "length":
            return True
        return False
    if reasoning_content:
        return True
    return finish_reason == "length"


def _glm_retry_diagnostics(data: dict, *, reason: str) -> dict:
    choice = data.get("choices", [{}])[0]
    message = choice.get("message", {})
    return {
        "reason": reason,
        "finish_reason": choice.get("finish_reason"),
        "content_excerpt": _trim_excerpt(_extract_message_content(message)),
        "reasoning_excerpt": _trim_excerpt(_extract_reasoning_content(message)),
        "usage": data.get("usage"),
    }


def _normalize_max_tokens_value(value: int | None) -> int | None:
    try:
        number = int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
    if number is None:
        return None
    return max(LLM_MIN_MAX_TOKENS, min(number, LLM_MAX_TOKENS_LIMIT))


def _request_timeout_seconds(llm_config: LLMConfig) -> float:
    model_name = (llm_config.model_name or "").lower()
    if (llm_config.provider_name or "").lower() == "glm" or model_name.startswith("glm"):
        return max(HTTP_TIMEOUT_SECONDS * 4, 60.0)
    if "reasoner" in model_name:
        return max(HTTP_TIMEOUT_SECONDS * 10, 150.0)
    return max(HTTP_TIMEOUT_SECONDS * 5, 75.0)


def _write_debug(debug_writer, *, stage: str, name: str, payload: object) -> None:
    if debug_writer is None:
        return
    try:
        debug_writer(stage=stage, name=name, payload=payload)
    except Exception:
        return


def _retry_backoff_seconds(attempt: int) -> float:
    return HTTP_RETRY_BASE_SECONDS * (2 ** max(attempt - 1, 0))


def _rate_limit_wait_seconds(response: httpx.Response, attempt: int) -> float:
    retry_after = response.headers.get("Retry-After", "").strip()
    if retry_after:
        try:
            seconds = float(retry_after)
            return max(seconds, 1.0)
        except ValueError:
            pass
    return min(_retry_backoff_seconds(attempt), 12.0)


def _format_rate_limit_error(response: httpx.Response, wait_seconds: float, attempts: int) -> str:
    detail = _extract_error_detail(response)
    wait_text = f"{int(wait_seconds)} 秒后" if wait_seconds >= 1 else "稍后"
    message = (
        f"模型接口触发限流或配额不足（HTTP 429），已自动重试 {attempts} 次仍失败。"
        f" 请{wait_text}重试，或降低并发任务数量、稍后再试、检查当前 API Key 的速率限制与剩余额度。"
    )
    if detail:
        message = f"{message} 供应商返回：{detail}"
    return message


def _format_http_error(response: httpx.Response) -> str:
    detail = _extract_error_detail(response)
    message = f"模型接口请求失败（HTTP {response.status_code}）。"
    if detail:
        message = f"{message} 供应商返回：{detail}"
    return message


def _format_original_http_error(exc: httpx.HTTPStatusError) -> str:
    raw = str(exc)
    body = _extract_raw_response_text(exc.response)
    if body:
        return f"{raw}\n\n响应体：\n{body}"
    return raw


def _extract_error_detail(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        payload = None

    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            for key in ("message", "msg", "detail", "code"):
                value = _optional_string(error.get(key))
                if value:
                    return value
        for key in ("message", "msg", "detail", "error_msg", "code"):
            value = _optional_string(payload.get(key))
            if value:
                return value

    text = _optional_string(response.text)
    if text:
        return _trim_excerpt(text, max_length=320)
    return None


def _extract_raw_response_text(response: httpx.Response) -> str | None:
    text = _optional_string(response.text)
    if text:
        return text[:3000]
    try:
        payload = response.json()
    except ValueError:
        return None
    return json.dumps(payload, ensure_ascii=False, indent=2)[:3000]


def _extract_message_content(message: dict) -> str:
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                if item.strip():
                    parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            text = item.get("text") or item.get("content")
            if isinstance(text, str) and text.strip():
                parts.append(text)
        return "\n".join(parts)
    return str(content)


def _extract_reasoning_content(message: dict) -> str:
    reasoning_content = message.get("reasoning_content", "")
    if isinstance(reasoning_content, str):
        return reasoning_content
    if isinstance(reasoning_content, list):
        parts: list[str] = []
        for item in reasoning_content:
            if isinstance(item, str):
                if item.strip():
                    parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            text = item.get("text") or item.get("content")
            if isinstance(text, str) and text.strip():
                parts.append(text)
        return "\n".join(parts)
    return str(reasoning_content)


def _extract_json_object(content: str) -> dict | None:
    for candidate in _candidate_json_strings(content):
        parsed = _parse_candidate_json(candidate)
        if isinstance(parsed, dict):
            return parsed
    return None


def _candidate_json_strings(content: str) -> list[str]:
    candidates: list[str] = []
    stripped = content.strip()
    if stripped:
        candidates.append(stripped)

    fenced_matches = re.findall(r"```(?:json)?\s*(.*?)```", content, flags=re.DOTALL | re.IGNORECASE)
    for block in fenced_matches:
        block = block.strip()
        if block:
            candidates.append(block)

    balanced = _find_balanced_json_object(content)
    if balanced:
        candidates.append(balanced)

    seen: set[str] = set()
    unique: list[str] = []
    for item in candidates:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
    return unique


def _parse_candidate_json(candidate: str) -> dict | None:
    normalized = candidate.strip()
    if not normalized:
        return None
    try:
        parsed = json.loads(normalized)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    repaired = normalized.replace("```json", "").replace("```JSON", "").replace("```", "").strip()
    try:
        parsed = json.loads(repaired)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    try:
        literal = ast.literal_eval(repaired)
        return literal if isinstance(literal, dict) else None
    except (SyntaxError, ValueError):
        return None


def _find_balanced_json_object(content: str) -> str | None:
    start_index = content.find("{")
    while start_index != -1:
        depth = 0
        in_string = False
        escape = False
        quote_char = ""
        for index in range(start_index, len(content)):
            char = content[index]
            if in_string:
                if escape:
                    escape = False
                    continue
                if char == "\\":
                    escape = True
                    continue
                if char == quote_char:
                    in_string = False
                continue
            if char in {'"', "'"}:
                in_string = True
                quote_char = char
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return content[start_index:index + 1]
        start_index = content.find("{", start_index + 1)
    return None


def _trim_excerpt(content: str, max_length: int = 240) -> str:
    compact = " ".join(content.split())
    if not compact:
        return "模型没有返回可用文本。"
    if len(compact) <= max_length:
        return compact
    return f"{compact[:max_length]}..."


def _glm_empty_content_hint(*, data: dict, endpoint: str, llm_config: LLMConfig, expect_json: bool) -> str:
    if not _is_glm_compatible(endpoint, llm_config):
        return ""
    choice = data.get("choices", [{}])[0]
    message = choice.get("message", {})
    content = _extract_message_content(message).strip()
    reasoning_content = _extract_reasoning_content(message).strip()
    finish_reason = str(choice.get("finish_reason") or "").strip().lower()
    if content and not expect_json:
        return ""
    if content and expect_json and _extract_json_object(content) is not None:
        return ""
    if not content and not reasoning_content and not finish_reason:
        return ""
    details: list[str] = []
    if finish_reason:
        details.append(f"finish_reason={finish_reason}")
    if reasoning_content and not content:
        details.append("模型仅返回 reasoning_content，未返回最终正文 content")
    elif content and expect_json and _extract_json_object(content) is None:
        details.append("最终正文存在，但不是完整 JSON")
    if not details:
        return ""
    return f" 诊断信息：{'；'.join(details)}。"


def _as_string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_reversibility(value: object) -> str | None:
    if isinstance(value, list):
        value = next((item for item in value if _optional_string(item)), None)
    text = _optional_string(value)
    if text in ALLOWED_REVERSIBILITY:
        return text
    return None


def _normalize_confidence(value: object) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return round(min(max(number, 0.0), 1.0), 2)


def _normalize_script_type(value: object) -> str | None:
    if isinstance(value, list):
        value = next((item for item in value if _optional_string(item)), None)
    text = _optional_string(value)
    if text in ALLOWED_SCRIPT_TYPES:
        return text
    return None


def _normalize_operations(value: object) -> list[str]:
    operations = _as_string_list(value)
    return [op for op in operations if op in ALLOWED_OPERATIONS]


def _normalize_observed_facts(value: object) -> list[str]:
    facts = _as_string_list(value)
    normalized: list[str] = []
    seen: set[str] = set()
    for item in facts:
        fact = item.replace("\n", " ").strip(" -")
        if not fact:
            continue
        if fact in seen:
            continue
        seen.add(fact)
        normalized.append(fact)
    return normalized


def _normalize_function_chain(value: object) -> list[str]:
    chain = _as_string_list(value)
    normalized: list[str] = []
    for item in chain:
        parts = [part.strip() for part in item.split("->") if part.strip()]
        if not parts:
            parts = [item]
        for part in parts:
            function_name = part.split(" @ ", 1)[0].strip()
            if not function_name:
                continue
            normalized.append(function_name)
    return normalized


def _normalize_key_material(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, str] = {}
    for key in (
        "seed_key",
        "seed_iv",
        "secret",
        "aes_key",
        "aes_iv",
        "aes_mode",
        "output",
    ):
        if key not in value:
            continue
        text = _optional_string(value.get(key))
        if text:
            normalized[key] = text
    for key in ("aes_key_bytes", "aes_iv_bytes"):
        if key not in value:
            continue
        number = _normalize_optional_positive_int(value.get(key))
        if number is not None:
            normalized[key] = str(number)
    derivation_steps = _as_string_list(value.get("derivation_steps"))
    if derivation_steps:
        normalized["derivation_steps"] = " | ".join(derivation_steps)
    return normalized


def _normalize_optional_positive_int(value: object) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _normalize_survey_result(value: object) -> dict:
    if not isinstance(value, dict):
        return {
            "global_summary": None,
            "relevant_files": [],
            "focus_targets": [],
            "suspected_function_chain": [],
            "suspected_operations": [],
            "reasoning_notes": [],
        }

    focus_targets: list[dict[str, object]] = []
    raw_targets = value.get("focus_targets")
    if isinstance(raw_targets, list):
        for item in raw_targets:
            if isinstance(item, dict):
                file_name = _optional_string(item.get("file"))
                function_name = _optional_string(item.get("function_name"))
                line_hint = _normalize_line_hint(item.get("line_hint"))
                reason = _optional_string(item.get("reason"))
                if file_name or function_name or line_hint is not None:
                    focus_targets.append(
                        {
                            "file": file_name,
                            "line_hint": line_hint,
                            "function_name": function_name,
                            "reason": reason,
                        }
                    )
                continue
            text = _optional_string(item)
            if text:
                focus_targets.append({"file": text, "line_hint": None, "function_name": None, "reason": None})

    return {
        "global_summary": _optional_string(value.get("global_summary")),
        "relevant_files": _as_string_list(value.get("relevant_files")),
        "focus_targets": focus_targets,
        "suspected_function_chain": _normalize_function_chain(value.get("suspected_function_chain")),
        "suspected_operations": _normalize_operations(value.get("suspected_operations")),
        "reasoning_notes": _as_string_list(value.get("reasoning_notes")),
    }


def _parse_survey_text_result(content: str) -> dict:
    sections = {
        "global_summary": [],
        "relevant_files": [],
        "focus_targets": [],
        "suspected_function_chain": [],
        "suspected_operations": [],
        "reasoning_notes": [],
    }
    section_map = {
        "全局摘要": "global_summary",
        "相关文件": "relevant_files",
        "重点目标": "focus_targets",
        "疑似函数链": "suspected_function_chain",
        "疑似操作": "suspected_operations",
        "备注": "reasoning_notes",
    }
    current_section: str | None = None
    for raw_line in (content or "").replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        header_match = re.match(r"^(全局摘要|相关文件|重点目标|疑似函数链|疑似操作|备注)\s*[：:]\s*(.*)$", line)
        if header_match:
            current_section = section_map[header_match.group(1)]
            remainder = header_match.group(2).strip()
            if remainder:
                sections[current_section].append(remainder)
            continue
        if current_section is None:
            continue
        sections[current_section].append(line)

    summary = " ".join(_clean_survey_summary_line(line) for line in sections["global_summary"] if _clean_survey_summary_line(line))
    relevant_files = _expand_survey_items(sections["relevant_files"])
    function_chain = _expand_survey_items(sections["suspected_function_chain"])
    operations = _expand_survey_items(sections["suspected_operations"])
    notes = _expand_survey_items(sections["reasoning_notes"])
    focus_targets = [
        target
        for target in (_parse_survey_focus_target(line) for line in sections["focus_targets"])
        if target is not None
    ]

    return {
        "global_summary": summary or None,
        "relevant_files": relevant_files,
        "focus_targets": focus_targets,
        "suspected_function_chain": function_chain,
        "suspected_operations": operations,
        "reasoning_notes": notes,
    }


def _survey_result_has_signal(value: dict) -> bool:
    return bool(
        value.get("global_summary")
        or value.get("relevant_files")
        or value.get("focus_targets")
        or value.get("suspected_function_chain")
        or value.get("suspected_operations")
        or value.get("reasoning_notes")
    )


def _clean_survey_summary_line(line: str) -> str:
    return _clean_survey_item(line)


def _expand_survey_items(lines: list[str]) -> list[str]:
    items: list[str] = []
    for line in lines:
        cleaned = _clean_survey_item(line)
        if not cleaned:
            continue
        if any(separator in cleaned for separator in ("、", "，", ",")):
            parts = re.split(r"[、，,]+", cleaned)
            items.extend(part.strip() for part in parts if part.strip())
            continue
        items.append(cleaned)
    return items


def _clean_survey_item(line: str) -> str:
    return re.sub(r"^\s*(?:[-*•]+|\d+[.)、])\s*", "", line or "").strip()


def _parse_survey_focus_target(line: str) -> dict[str, object] | None:
    cleaned = _clean_survey_item(line)
    if not cleaned:
        return None
    target: dict[str, object] = {"file": None, "line_hint": None, "function_name": None, "reason": None}
    residual_parts: list[str] = []
    for part in [segment.strip() for segment in cleaned.split("|") if segment.strip()]:
        label, value = _split_label_value(part)
        if label is None:
            residual_parts.append(part)
            continue
        normalized_label = label.lower()
        if normalized_label in {"file", "文件"}:
            target["file"] = value or None
        elif normalized_label in {"line", "line_hint", "行", "行号"}:
            target["line_hint"] = _extract_int(value)
        elif normalized_label in {"function", "function_name", "函数", "函数名"}:
            target["function_name"] = value or None
        elif normalized_label in {"reason", "原因", "说明"}:
            target["reason"] = value or None
        else:
            residual_parts.append(part)
    if residual_parts and not target["reason"]:
        target["reason"] = "；".join(residual_parts)
    if any(value for value in target.values()):
        return target
    return {"file": cleaned, "line_hint": None, "function_name": None, "reason": None}


def _split_label_value(text: str) -> tuple[str | None, str]:
    for separator in ("=", "：", ":"):
        if separator in text:
            label, value = text.split(separator, 1)
            return label.strip(), value.strip()
    return None, text.strip()


def _extract_int(text: str) -> int | None:
    match = re.search(r"\d+", text or "")
    if not match:
        return None
    try:
        return int(match.group(0))
    except ValueError:
        return None


def _normalize_line_hint(value: object) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None
