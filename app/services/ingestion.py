from __future__ import annotations

import io
import zipfile
from pathlib import Path

from fastapi import UploadFile

from app.config import MAX_ARCHIVE_MEMBERS
from app.models import SourceArtifact
from app.services.fetcher import discover_js_from_page, fetch_explicit_js_urls
from app.services.storage import decode_bytes, persist_source


JS_SUFFIXES = {".js", ".mjs", ".cjs"}
TEXT_SUFFIXES = JS_SUFFIXES | {".txt"}


async def collect_sources(
    *,
    run_dir: Path,
    webpage_url: str | None,
    external_js_urls: list[str],
    uploads: list[UploadFile],
) -> tuple[list[SourceArtifact], list[str], list[str]]:
    collected: list[SourceArtifact] = []
    notes: list[str] = []
    warnings: list[str] = []
    seen_hashes: set[str] = set()

    def register(source: SourceArtifact) -> None:
        if source.content_hash in seen_hashes:
            warnings.append(f"检测到重复源码，已跳过：{source.name}")
            return
        seen_hashes.add(source.content_hash)
        collected.append(source)

    for upload in uploads:
        if not upload.filename:
            continue
        raw = await upload.read()
        suffix = Path(upload.filename).suffix.lower()
        if suffix == ".zip":
            extracted, zip_notes, zip_warnings = _extract_zip_sources(run_dir, upload.filename, raw)
            notes.extend(zip_notes)
            warnings.extend(zip_warnings)
            for source in extracted:
                register(source)
            continue
        if suffix in TEXT_SUFFIXES:
            content = decode_bytes(raw)
            register(
                persist_source(
                    run_dir,
                    name=upload.filename,
                    content=content,
                    origin="upload",
                    notes=["由用户直接上传。"],
                )
            )
            continue
        warnings.append(f"不支持的上传类型，已跳过：{upload.filename}")

    if webpage_url:
        remote_sources, remote_notes, remote_warnings = await discover_js_from_page(webpage_url)
        notes.extend(remote_notes)
        warnings.extend(remote_warnings)
        for remote in remote_sources:
            register(
                persist_source(
                    run_dir,
                    name=remote.name,
                    content=remote.content,
                    origin=remote.origin,
                    source_url=remote.source_url,
                    discovered_from=remote.discovered_from,
                    notes=remote.notes,
                )
            )

    if external_js_urls:
        remote_sources, remote_notes, remote_warnings = await fetch_explicit_js_urls(external_js_urls)
        notes.extend(remote_notes)
        warnings.extend(remote_warnings)
        for remote in remote_sources:
            register(
                persist_source(
                    run_dir,
                    name=remote.name,
                    content=remote.content,
                    origin=remote.origin,
                    source_url=remote.source_url,
                    discovered_from=remote.discovered_from,
                    notes=remote.notes,
                )
            )

    if collected:
        notes.append(f"本次共收集到 {len(collected)} 份唯一 JS 源码。")
    return collected, notes, warnings


def reuse_sources_from_run(
    *,
    run_dir: Path,
    draft_run_dir: Path,
) -> tuple[list[SourceArtifact], list[str], list[str]]:
    collected: list[SourceArtifact] = []
    notes: list[str] = []
    warnings: list[str] = []
    source_dir = draft_run_dir / "sources"
    if not source_dir.exists():
        warnings.append("草稿任务中没有可复用的源码文件。")
        return collected, notes, warnings

    for source_path in sorted(source_dir.iterdir()):
        if not source_path.is_file():
            continue
        try:
            content = source_path.read_text(encoding="utf-8")
        except Exception as exc:
            warnings.append(f"复用草稿源码失败：{source_path.name}，原因：{exc}")
            continue
        collected.append(
            persist_source(
                run_dir,
                name=source_path.name,
                content=content,
                origin="upload",
                notes=[f"复用自草稿任务 {draft_run_dir.name} 的已收集源码。"],
            )
        )

    if collected:
        notes.append(f"已从草稿任务 {draft_run_dir.name} 复用 {len(collected)} 份源码。")
    return collected, notes, warnings


def _extract_zip_sources(run_dir: Path, archive_name: str, raw: bytes) -> tuple[list[SourceArtifact], list[str], list[str]]:
    extracted: list[SourceArtifact] = []
    notes: list[str] = []
    warnings: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()[:MAX_ARCHIVE_MEMBERS]
            notes.append(f"已读取压缩包 {archive_name} 中的 {len(members)} 个成员。")
            for member in members:
                if member.is_dir():
                    continue
                suffix = Path(member.filename).suffix.lower()
                if suffix not in TEXT_SUFFIXES:
                    continue
                try:
                    content = decode_bytes(archive.read(member))
                except Exception as exc:
                    warnings.append(f"读取压缩包文件 {member.filename} 失败：{exc}")
                    continue
                extracted.append(
                    persist_source(
                        run_dir,
                        name=Path(member.filename).name,
                        content=content,
                        origin="zip",
                        notes=[f"从压缩包 {archive_name} 中解压得到。"],
                    )
                )
    except zipfile.BadZipFile:
        warnings.append(f"上传文件不是有效的 ZIP 压缩包：{archive_name}")
    return extracted, notes, warnings
