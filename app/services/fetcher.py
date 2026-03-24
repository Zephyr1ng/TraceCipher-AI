from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from app.config import HTTP_TIMEOUT_SECONDS, MAX_DIRECT_JS, MAX_DISCOVERED_CHUNKS, MAX_SOURCE_BYTES
from app.services.storage import decode_bytes


SCRIPT_URL_PATTERN = re.compile(r"""["'`](?P<path>(?:https?:)?//[^"'`]+?\.js(?:\?[^"'`]+)?|/[^"'`]+?\.js(?:\?[^"'`]+)?|(?:\./|\.\./)?[^"'`\s]+?\.js(?:\?[^"'`]+)?)["'`]""")


@dataclass(slots=True)
class RemoteJS:
    name: str
    content: str
    source_url: str
    origin: str
    discovered_from: str | None = None
    notes: list[str] = field(default_factory=list)


async def discover_js_from_page(page_url: str) -> tuple[list[RemoteJS], list[str], list[str]]:
    notes: list[str] = []
    warnings: list[str] = []
    async with _client() as client:
        try:
            response = await client.get(page_url)
            response.raise_for_status()
        except Exception as exc:
            return [], notes, [f"抓取网页 {page_url} 失败：{exc}"]
        soup = BeautifulSoup(response.text, "html.parser")
        direct_urls: list[str] = []
        for tag in soup.find_all("script", src=True):
            script_url = urljoin(str(response.url), tag.get("src", ""))
            if script_url.endswith(".js") or ".js?" in script_url:
                direct_urls.append(script_url)
        direct_urls = _dedupe(direct_urls)[:MAX_DIRECT_JS]
        notes.append(f"当前页面共发现 {len(direct_urls)} 个直接引用的 JS 文件。")
        fetched: list[RemoteJS] = []
        seen_urls = set(direct_urls)
        for script_url in direct_urls:
            remote = await fetch_js_url(script_url, origin="webpage", client=client)
            if remote is not None:
                fetched.append(remote)
        chunk_urls: list[str] = []
        for remote in fetched:
            chunk_urls.extend(_discover_chunk_urls(remote.content, remote.source_url))
        chunk_urls = [url for url in _dedupe(chunk_urls) if url not in seen_urls][:MAX_DISCOVERED_CHUNKS]
        if chunk_urls:
            notes.append(f"从直接脚本中静态发现了 {len(chunk_urls)} 个候选 chunk。")
        for chunk_url in chunk_urls:
            seen_urls.add(chunk_url)
            remote = await fetch_js_url(
                chunk_url,
                origin="webpage",
                discovered_from="static-chunk-discovery",
                client=client,
            )
            if remote is not None:
                fetched.append(remote)
        return fetched, notes, warnings


async def fetch_explicit_js_urls(urls: list[str]) -> tuple[list[RemoteJS], list[str], list[str]]:
    notes: list[str] = []
    warnings: list[str] = []
    fetched: list[RemoteJS] = []
    async with _client() as client:
        for url in _dedupe(urls):
            remote = await fetch_js_url(url, origin="external_url", client=client)
            if remote is None:
                warnings.append(f"抓取外部 JS URL 失败：{url}")
                continue
            fetched.append(remote)
        if fetched:
            notes.append(f"已从外部 URL 成功抓取 {len(fetched)} 个 JS 文件。")
    return fetched, notes, warnings


async def fetch_js_url(
    url: str,
    *,
    origin: str,
    client: httpx.AsyncClient,
    discovered_from: str | None = None,
) -> RemoteJS | None:
    try:
        response = await client.get(url)
        response.raise_for_status()
    except Exception:
        return None
    raw = await response.aread()
    if len(raw) > MAX_SOURCE_BYTES:
        content = decode_bytes(raw[:MAX_SOURCE_BYTES])
        notes = [f"源码过大，已截断到 {MAX_SOURCE_BYTES} 字节。"]
    else:
        content = decode_bytes(raw)
        notes = []
    name = response.url.path.rsplit("/", 1)[-1] or "remote.js"
    return RemoteJS(
        name=name,
        content=content,
        source_url=str(response.url),
        origin=origin,
        discovered_from=discovered_from,
        notes=notes,
    )


def _discover_chunk_urls(content: str, base_url: str) -> list[str]:
    discovered: list[str] = []
    for match in SCRIPT_URL_PATTERN.finditer(content):
        raw_path = match.group("path")
        if any(token in raw_path for token in ("${", "[name]", "sourceMappingURL=", "data:")):
            continue
        if raw_path.endswith(".map") or ".map?" in raw_path:
            continue
        discovered.append(urljoin(base_url, raw_path))
    return discovered


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=HTTP_TIMEOUT_SECONDS,
        follow_redirects=True,
        headers={"User-Agent": "JSParameterAnalyzer/0.1"},
    )
