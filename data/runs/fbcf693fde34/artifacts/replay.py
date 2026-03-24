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

PARAMETER_NAME = 'password'
REVERSIBILITY = 'potentially-reversible-encryption'
MODE = 'CBC'
KEY = '288146ljx288146l'.encode("utf-8")
IV = '2881462881462881'.encode("utf-8")
OUTPUT_HEX = False


def _build_cipher():
    if MODE == "CBC":
        return AES.new(KEY, AES.MODE_CBC, IV)
    if MODE == "ECB":
        return AES.new(KEY, AES.MODE_ECB)
    raise ValueError(f"暂不支持的 AES 模式：{MODE}")


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
