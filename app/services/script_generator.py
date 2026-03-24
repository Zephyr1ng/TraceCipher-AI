from __future__ import annotations
import base64
import hashlib
import hmac
import json
import re
import textwrap
from pathlib import Path
from typing import Any

from app.models import CandidateTrace, GeneratedArtifact, LLMInsight


OPERATION_ALIASES = {
    "json": ["json.stringify", "json.parse"],
    "urlencode": ["encodeuricomponent", "decodeuricomponent"],
    "base64": ["btoa", "atob", "base64"],
    "hex": ["toString(CryptoJS.enc.Hex)", "enc.hex", "hex", "binascii.hexlify", "toString(16)"],
    "md5": ["md5"],
    "sha1": ["sha1"],
    "sha256": ["sha256"],
    "sha512": ["sha512"],
    "hmac": ["hmac", "hmacsha"],
    "aes": ["aes.encrypt", "aes.decrypt", "cryptojs.aes", "mode.cbc", "mode.ecb"],
}


def generate_artifacts(
    *,
    run_dir: Path,
    parameter_name: str,
    parameter_type: str,
    reversibility: str,
    candidates: list[CandidateTrace],
    source_contents: dict[str, str],
    llm_insight: LLMInsight,
) -> tuple[GeneratedArtifact, dict[str, Any]]:
    artifacts_dir = run_dir / "artifacts"
    top_candidate = candidates[0] if candidates else None
    llm_operations = list(llm_insight.inferred_operations)
    llm_key_material = dict(llm_insight.key_material)
    preferred_script_type = llm_insight.preferred_script_type

    if top_candidate is None and not llm_operations and not llm_key_material:
        artifact = GeneratedArtifact(
            script_type="report-only",
            notes=["大模型未提供足够稳定的结构化信息，暂时无法生成复现脚本。"],
        )
        return artifact, {"kind": "none"}

    source_text = source_contents.get(top_candidate.file_name, "") if top_candidate else ""
    ordered_ops = llm_operations or (infer_operations(top_candidate) if top_candidate else [])

    if "aes" in ordered_ops or (top_candidate and "aes" in top_candidate.markers) or llm_key_material.get("aes_key"):
        aes_meta = _resolve_aes_metadata(source_text, llm_key_material)
        if _is_valid_aes_meta(aes_meta):
            script_path = artifacts_dir / "replay.py"
            script_path.write_text(
                _render_aes_script(parameter_name, reversibility, aes_meta),
                encoding="utf-8",
            )
            artifact = GeneratedArtifact(
                script_type="pure-python",
                files=[f"artifacts/{script_path.name}"],
                runtime="python3",
                dependencies=["pycryptodome"],
                notes=["AES 相关参数完全来自大模型结构化分析结果。"],
            )
            return artifact, {"kind": "aes", "meta": aes_meta}

    if ordered_ops:
        unsupported_special_ops = {"aes", "rsa"} & set(ordered_ops)
        if unsupported_special_ops:
            ordered_ops = []

    if ordered_ops:
        secret = llm_key_material.get("secret") or (
            _extract_secret(source_text) if top_candidate and ("hmac" in top_candidate.markers or "hmac" in ordered_ops) else None
        )
        script_path = artifacts_dir / "replay.py"
        script_path.write_text(
            _render_operation_script(
                parameter_name=parameter_name,
                parameter_type=parameter_type,
                reversibility=reversibility,
                operations=ordered_ops,
                secret=secret,
            ),
            encoding="utf-8",
        )
        dependencies: list[str] = []
        if "aes" in ordered_ops:
            dependencies.append("pycryptodome")
        artifact = GeneratedArtifact(
            script_type="pure-python",
            files=[f"artifacts/{script_path.name}"],
            runtime="python3",
            dependencies=dependencies,
            notes=["复现脚本主要依据大模型推断出的操作链生成。"],
        )
        return artifact, {"kind": "operations", "operations": ordered_ops, "secret": secret}

    bridge_block_reason = _bridge_block_reason(
        reversibility=reversibility,
        preferred_script_type=preferred_script_type,
        ordered_ops=ordered_ops,
        llm_key_material=llm_key_material,
    )
    if bridge_block_reason:
        artifact = GeneratedArtifact(
            script_type="report-only",
            notes=[bridge_block_reason],
        )
        return artifact, {"kind": "none", "blocked_bridge": True}

    artifact = GeneratedArtifact(
        script_type="report-only",
        notes=["虽然定位到了疑似链路，但当前证据仍不足以合成稳定可运行的复现脚本。"],
    )
    return artifact, {"kind": "none"}


def validate_artifact(
    *,
    validation_plaintext: str | None,
    validation_ciphertext: str | None,
    generation_context: dict[str, Any],
) -> tuple[str, list[str]]:
    details: list[str] = []
    if not validation_plaintext and not validation_ciphertext:
        if generation_context.get("kind") == "none":
            return "partial", ["本次仅完成了结构合理性检查，当前结果还没有可执行脚本。"]
        return "partial", ["本次仅完成了结构合理性检查，尚未提供已知样本对进行强校验。"]

    kind = generation_context.get("kind")
    if kind == "operations" and validation_plaintext is not None and validation_ciphertext is not None:
        try:
            computed = _replay_operations(
                validation_plaintext,
                generation_context.get("operations", []),
                generation_context.get("secret"),
            )
        except Exception as exc:
            return "partial", [f"样本对校验未完成：{exc}"]
        if computed == validation_ciphertext:
            return "passed", ["样本对校验通过，推断出的操作链可以复现目标结果。"]
        return "failed", [f"样本对校验失败，计算得到的结果为：{computed}"]

    if kind == "aes" and validation_plaintext and validation_ciphertext:
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
        except ImportError:
            return "partial", ["AES 校验已跳过，因为当前应用环境未安装 pycryptodome。"]
        meta = generation_context["meta"]
        encrypted = _encrypt_aes(validation_plaintext, meta, AES, pad)
        details.append(f"AES 计算得到的密文为：{encrypted}")
        if encrypted == validation_ciphertext:
            return "passed", ["AES 样本对校验通过。"]
        if _decrypt_aes(validation_ciphertext, meta, AES, unpad) == validation_plaintext:
            return "passed", ["AES 反向校验通过，已能还原提供的明文。"]
        return "failed", details

    return "partial", ["当前脚本类型暂不支持自动样本对校验。"]


def infer_operations(candidate: CandidateTrace) -> list[str]:
    ordered: list[tuple[int, str]] = []
    snippet_lower = candidate.snippet.lower()
    for op_name, aliases in OPERATION_ALIASES.items():
        positions = [snippet_lower.find(alias) for alias in aliases if snippet_lower.find(alias) != -1]
        if positions:
            ordered.append((min(positions), op_name))
    ordered.sort(key=lambda item: item[0])
    unique: list[str] = []
    for _, op_name in ordered:
        if op_name not in unique:
            unique.append(op_name)
    return unique


def _extract_secret(source_text: str) -> str | None:
    patterns = [
        r"""(?:secret|appSecret|apiSecret|signKey|hmacKey)\s*[:=]\s*["']([^"'`]+)["']""",
        r"""(?:key)\s*[:=]\s*["']([^"'`]{4,128})["']""",
    ]
    for pattern in patterns:
        match = re.search(pattern, source_text, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _extract_aes_metadata(source_text: str) -> dict[str, str]:
    key = _find_named_literal(source_text, "key")
    iv = _find_named_literal(source_text, "iv")
    mode = "CBC" if "mode.CBC" in source_text or "mode:CryptoJS.mode.CBC" in source_text else "ECB"
    output = "base64"
    if "Hex" in source_text and "Base64" not in source_text:
        output = "hex"
    return {
        "key": key or "",
        "iv": iv or "",
        "mode": mode,
        "output": output,
    }


def _resolve_aes_metadata(source_text: str, llm_key_material: dict[str, str]) -> dict[str, str]:
    return {
        "key": llm_key_material.get("aes_key", ""),
        "iv": llm_key_material.get("aes_iv", ""),
        "mode": llm_key_material.get("aes_mode", ""),
        "output": llm_key_material.get("output", ""),
    }


def _bridge_block_reason(
    *,
    reversibility: str,
    preferred_script_type: str | None,
    ordered_ops: list[str],
    llm_key_material: dict[str, str],
) -> str | None:
    if reversibility not in {"potentially-reversible-encryption", "reversible-transform"}:
        return None
    if preferred_script_type != "pure-python":
        return None
    has_aes = "aes" in ordered_ops or any(key.startswith("aes_") for key in llm_key_material)
    if not has_aes:
        return None
    aes_meta = {
        "key": llm_key_material.get("aes_key", ""),
        "iv": llm_key_material.get("aes_iv", ""),
        "mode": llm_key_material.get("aes_mode", ""),
        "output": llm_key_material.get("output", ""),
    }
    if _is_valid_aes_meta(aes_meta):
        return None
    return "模型结果存在自相矛盾：已判断为可逆且倾向 pure-python，但当前返回的 AES key/iv 或脚本条件仍不满足要求，请继续复核。"


def _is_valid_aes_meta(meta: dict[str, str]) -> bool:
    key_length = len(meta.get("key", "").encode("utf-8"))
    if key_length not in {16, 24, 32}:
        return False
    if meta.get("mode") not in {"CBC", "ECB"}:
        return False
    if meta.get("output") not in {"base64", "hex"}:
        return False
    if meta.get("mode") == "CBC":
        iv_length = len(meta.get("iv", "").encode("utf-8"))
        return iv_length == 16
    return True


def _find_named_literal(source_text: str, variable_name: str) -> str | None:
    patterns = [
        rf"""{variable_name}\s*[:=]\s*CryptoJS\.enc\.Utf8\.parse\(\s*["']([^"']+)["']\s*\)""",
        rf"""{variable_name}\s*[:=]\s*["']([^"'`]+)["']""",
        rf"""{variable_name}\s*[:=]\s*`([^`]+)`""",
    ]
    for pattern in patterns:
        match = re.search(pattern, source_text, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _render_operation_script(
    *,
    parameter_name: str,
    parameter_type: str,
    reversibility: str,
    operations: list[str],
    secret: str | None,
) -> str:
    operation_json = json.dumps(operations)
    secret_literal = repr(secret) if secret is not None else "None"
    return textwrap.dedent(
        f"""
        import argparse
        import base64
        import binascii
        import hashlib
        import hmac
        import json
        from urllib.parse import quote, unquote

        PARAMETER_NAME = {parameter_name!r}
        PARAMETER_TYPE = {parameter_type!r}
        REVERSIBILITY = {reversibility!r}
        OPERATIONS = {operation_json}
        SECRET = {secret_literal}


        def encrypt(value: str) -> str:
            current = value
            for operation in OPERATIONS:
                if operation == "json":
                    current = json.dumps(current, ensure_ascii=False, separators=(",", ":"))
                elif operation == "urlencode":
                    current = quote(current, safe="")
                elif operation == "base64":
                    current = base64.b64encode(current.encode("utf-8")).decode("utf-8")
                elif operation == "hex":
                    current = binascii.hexlify(current.encode("utf-8")).decode("utf-8")
                elif operation == "md5":
                    current = hashlib.md5(current.encode("utf-8")).hexdigest()
                elif operation == "sha1":
                    current = hashlib.sha1(current.encode("utf-8")).hexdigest()
                elif operation == "sha256":
                    current = hashlib.sha256(current.encode("utf-8")).hexdigest()
                elif operation == "sha512":
                    current = hashlib.sha512(current.encode("utf-8")).hexdigest()
                elif operation == "hmac":
                    if not SECRET:
                        raise ValueError("未能从源码中恢复出 HMAC 密钥。")
                    current = hmac.new(SECRET.encode("utf-8"), current.encode("utf-8"), hashlib.sha256).hexdigest()
                else:
                    raise ValueError(f"暂不支持的操作：{{operation}}")
            return current


        def decrypt(value: str) -> str:
            irreversible = {{"md5", "sha1", "sha256", "sha512", "hmac"}}
            if any(operation in irreversible for operation in OPERATIONS):
                raise ValueError(f"参数 {{PARAMETER_NAME}} 包含不可逆的签名或摘要步骤：{{OPERATIONS}}")
            current = value
            for operation in reversed(OPERATIONS):
                if operation == "base64":
                    current = base64.b64decode(current.encode("utf-8")).decode("utf-8")
                elif operation == "hex":
                    current = binascii.unhexlify(current.encode("utf-8")).decode("utf-8")
                elif operation == "urlencode":
                    current = unquote(current)
                elif operation == "json":
                    current = json.loads(current)
                else:
                    raise ValueError(f"暂不支持的逆向操作：{{operation}}")
            if not isinstance(current, str):
                current = json.dumps(current, ensure_ascii=False)
            return current


        def main() -> None:
            parser = argparse.ArgumentParser(description="复现推断出的 JS 参数变换链。")
            parser.add_argument("mode", choices=["encrypt", "decrypt"])
            parser.add_argument("value", help="根据模式输入明文或密文。")
            args = parser.parse_args()
            if args.mode == "encrypt":
                print(encrypt(args.value))
                return
            print(decrypt(args.value))


        if __name__ == "__main__":
            main()
        """
    ).strip() + "\n"


def _render_aes_script(parameter_name: str, reversibility: str, meta: dict[str, str]) -> str:
    iv_assignment = (
        f'IV = {meta["iv"]!r}.encode("utf-8")'
        if meta["mode"] == "CBC"
        else "IV = None"
    )
    output_hex = meta["output"] == "hex"
    return textwrap.dedent(
        f"""
        import argparse
        import base64
        import binascii
        import sys

        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
        except ImportError as exc:
            raise SystemExit(
                "当前 Python 环境缺少 pycryptodome。请在运行该脚本的解释器环境中执行：pip install pycryptodome"
            ) from exc

        PARAMETER_NAME = {parameter_name!r}
        REVERSIBILITY = {reversibility!r}
        MODE = {meta["mode"]!r}
        KEY = {meta["key"]!r}.encode("utf-8")
        {iv_assignment}
        OUTPUT_HEX = {output_hex}


        def _build_cipher():
            if MODE == "CBC":
                return AES.new(KEY, AES.MODE_CBC, IV)
            if MODE == "ECB":
                return AES.new(KEY, AES.MODE_ECB)
            raise ValueError(f"暂不支持的 AES 模式：{{MODE}}")


        def encrypt(value: str) -> str:
            cipher = _build_cipher()
            encrypted = cipher.encrypt(pad(value.encode("utf-8"), AES.block_size))
            if OUTPUT_HEX:
                return binascii.hexlify(encrypted).decode("utf-8")
            return base64.b64encode(encrypted).decode("utf-8")


        def decrypt(value: str) -> str:
            raw = binascii.unhexlify(value) if OUTPUT_HEX else base64.b64decode(value)
            cipher = _build_cipher()
            return unpad(cipher.decrypt(raw), AES.block_size).decode("utf-8")


        def main() -> None:
            parser = argparse.ArgumentParser(description="复现推断出的 AES 参数加解密流程。")
            parser.add_argument("mode", choices=["encrypt", "decrypt"])
            parser.add_argument("value")
            args = parser.parse_args()
            if args.mode == "encrypt":
                print(encrypt(args.value))
                return
            print(decrypt(args.value))


        if __name__ == "__main__":
            main()
        """
    ).strip() + "\n"




def _replay_operations(value: str, operations: list[str], secret: str | None) -> str:
    current = value
    for operation in operations:
        if operation == "json":
            current = json.dumps(current, ensure_ascii=False, separators=(",", ":"))
        elif operation == "urlencode":
            from urllib.parse import quote

            current = quote(current, safe="")
        elif operation == "base64":
            current = base64.b64encode(current.encode("utf-8")).decode("utf-8")
        elif operation == "md5":
            current = hashlib.md5(current.encode("utf-8")).hexdigest()
        elif operation == "sha1":
            current = hashlib.sha1(current.encode("utf-8")).hexdigest()
        elif operation == "sha256":
            current = hashlib.sha256(current.encode("utf-8")).hexdigest()
        elif operation == "sha512":
            current = hashlib.sha512(current.encode("utf-8")).hexdigest()
        elif operation == "hmac":
            if not secret:
                raise ValueError("缺少 HMAC 密钥。")
            current = hmac.new(secret.encode("utf-8"), current.encode("utf-8"), hashlib.sha256).hexdigest()
    return current


def _encrypt_aes(value: str, meta: dict[str, str], AES: Any, pad: Any) -> str:
    key = meta["key"].encode("utf-8")
    if meta["mode"] == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, meta["iv"].encode("utf-8"))
    else:
        cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(value.encode("utf-8"), AES.block_size))
    if meta["output"] == "hex":
        import binascii

        return binascii.hexlify(encrypted).decode("utf-8")
    return base64.b64encode(encrypted).decode("utf-8")


def _decrypt_aes(value: str, meta: dict[str, str], AES: Any, unpad: Any) -> str:
    if meta["output"] == "hex":
        import binascii

        raw = binascii.unhexlify(value)
    else:
        raw = base64.b64decode(value)
    key = meta["key"].encode("utf-8")
    if meta["mode"] == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, meta["iv"].encode("utf-8"))
    else:
        cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(raw), AES.block_size).decode("utf-8")
