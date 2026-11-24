import argparse
import os
import sys
import tempfile
from pathlib import Path

from lab4_des import (
    DesError,
    decode_des_key,
    decode_hex_block,
    decrypt_text_cbc,
    des_block,
    encrypt_text_cbc,
    format_block_trace,
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


def _atomic_write_text(path, text):
    destination = Path(path)
    if destination.exists() and not destination.is_file():
        raise DesError(f"Шлях результату не є файлом: {destination}")
    if not destination.parent.is_dir():
        raise DesError(f"Каталог для запису не існує: {destination.parent}")
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(text)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _read_utf8(path):
    try:
        return Path(path).read_bytes().decode("utf-8", errors="strict")
    except FileNotFoundError:
        raise DesError(f"Файл не знайдено: {path}") from None
    except UnicodeDecodeError:
        raise DesError(f"Файл не є коректним UTF-8: {path}") from None
    except IsADirectoryError:
        raise DesError(f"Очікувався файл, але отримано каталог: {path}") from None


def _read_key(args):
    sources = [args.key is not None, args.key_file is not None, args.key_stdin]
    if sum(1 for value in sources if value) != 1:
        raise DesError("Вкажіть рівно один спосіб передавання ключа: --key, --key-file або --key-stdin.")
    if args.key is not None:
        value = args.key
    elif args.key_file is not None:
        value = _read_utf8(args.key_file).strip()
    else:
        value = sys.stdin.read().strip()
    if not value:
        raise DesError("Ключ не може бути порожнім.")
    return decode_des_key(value)


def _read_text_input(args, allow_stdin=True):
    sources = [args.text is not None, args.input is not None]
    if allow_stdin:
        sources.append(args.stdin)
    if sum(1 for value in sources if value) != 1:
        choices = "--text, --input" + (" або --stdin" if allow_stdin else "")
        raise DesError(f"Вкажіть рівно один спосіб передавання даних: {choices}.")
    if args.text is not None:
        return args.text
    if args.input is not None:
        return _read_utf8(args.input)
    return sys.stdin.read()


def _read_block_hex(args):
    if bool(args.block) == bool(args.block_file):
        raise DesError("Вкажіть HEX-блок через --block або --block-file.")
    if args.block_file is not None:
        return _read_utf8(args.block_file).strip()
    return args.block.strip()


def _read_package(args):
    if sum(1 for value in (args.package is not None, args.package_file is not None) if value) != 1:
        raise DesError("Вкажіть Base64-пакет через --package або --package-file.")
    if args.package_file is not None:
        return _read_utf8(args.package_file).strip()
    return args.package.strip()


def _read_test_iv(value):
    if value is None:
        return None
    compact = value.strip()
    if len(compact) != 16:
        raise DesError("Тестовий IV має містити рівно 16 шістнадцяткових символів.")
    try:
        int(compact, 16)
        iv = bytes.fromhex(compact)
    except ValueError as error:
        raise DesError("Тестовий IV містить некоректні шістнадцяткові символи.") from error
    return iv


def _output_result(text, output_path):
    if output_path:
        _atomic_write_text(output_path, text)
    else:
        sys.stdout.write(text)


def _build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Лабораторна робота 4: навчальна реалізація DES для одного блока та DES CBC для UTF-8 тексту."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    block = subparsers.add_parser("block", help="Операції з одним 64-бітовим DES-блоком.")
    block_sub = block.add_subparsers(dest="operation", required=True)

    for operation, help_text in (
        ("encrypt", "Зашифрувати один 64-бітовий блок (16 HEX символів)."),
        ("decrypt", "Розшифрувати один 64-бітовий блок (16 HEX символів)."),
    ):
        command = block_sub.add_parser(operation, help=help_text)
        block_source = command.add_mutually_exclusive_group(required=True)
        block_source.add_argument("--block", help="HEX-представлення блока (16 символів).")
        block_source.add_argument("--block-file", help="Файл UTF-8 з HEX-блоком.")
        key_source = command.add_mutually_exclusive_group(required=True)
        key_source.add_argument("--key", help="HEX-ключ DES (16 символів, навчальні публічні дані).")
        key_source.add_argument("--key-file", help="Файл UTF-8 з HEX-ключем.")
        key_source.add_argument(
            "--key-stdin",
            action="store_true",
            help="Прочитати HEX-ключ зі стандартного вводу.",
        )
        command.add_argument("--trace", action="store_true", help="Показати трасування контрольного блока.")
        command.add_argument("--output", help="Файл UTF-8 для запису результату.")

    text = subparsers.add_parser("text", help="DES CBC для UTF-8 тексту з PKCS#7 та Base64-пакетом.")
    text_sub = text.add_subparsers(dest="operation", required=True)

    encrypt = text_sub.add_parser("encrypt", help="Зашифрувати UTF-8 текст у Base64(IV||шифротекст).")
    encrypt_input = encrypt.add_mutually_exclusive_group(required=True)
    encrypt_input.add_argument("--text", help="Відкритий текст у UTF-8 (для прикладів/тестів).")
    encrypt_input.add_argument("--input", help="Файл UTF-8 з відкритим текстом.")
    encrypt_input.add_argument("--stdin", action="store_true", help="Прочитати відкритий текст зі stdin.")
    encrypt_key = encrypt.add_mutually_exclusive_group(required=True)
    encrypt_key.add_argument("--key", help="HEX-ключ DES (16 символів, навчальні публічні дані).")
    encrypt_key.add_argument("--key-file", help="Файл UTF-8 з HEX-ключем.")
    encrypt_key.add_argument("--key-stdin", action="store_true", help="Прочитати HEX-ключ зі stdin.")
    encrypt.add_argument(
        "--test-iv",
        help="Фіксований 8-байтовий IV у HEX лише для відтворюваних тестів; у звичайній роботі не використовувати.",
    )
    encrypt.add_argument("--output", help="Файл UTF-8 для Base64-пакета.")

    decrypt = text_sub.add_parser("decrypt", help="Розшифрувати Base64(IV||шифротекст) у UTF-8 текст.")
    decrypt_input = decrypt.add_mutually_exclusive_group(required=True)
    decrypt_input.add_argument("--package", help="Base64-пакет IV||шифротекст.")
    decrypt_input.add_argument("--package-file", help="Файл UTF-8 з Base64-пакетом.")
    decrypt_key = decrypt.add_mutually_exclusive_group(required=True)
    decrypt_key.add_argument("--key", help="HEX-ключ DES (16 символів, навчальні публічні дані).")
    decrypt_key.add_argument("--key-file", help="Файл UTF-8 з HEX-ключем.")
    decrypt_key.add_argument("--key-stdin", action="store_true", help="Прочитати HEX-ключ зі stdin.")
    decrypt.add_argument("--output", help="Файл UTF-8 для відновленого тексту.")

    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        key = _read_key(args)
        if args.command == "block":
            block = decode_hex_block(_read_block_hex(args))
            decrypt = args.operation == "decrypt"
            if args.trace:
                result, trace = des_block(block, key, decrypt=decrypt, trace=True)
                output = format_block_trace(trace, decrypt=decrypt) + "\n\nРезультат: " + result.hex().upper()
            else:
                result = des_block(block, key, decrypt=decrypt)
                output = result.hex().upper()
            _output_result(output, args.output)
            return 0

        if args.command == "text":
            if args.operation == "encrypt":
                plaintext = _read_text_input(args)
                iv = _read_test_iv(args.test_iv)
                package = encrypt_text_cbc(plaintext, key, iv=iv)
                _output_result(package, args.output)
                return 0
            package = _read_package(args)
            plaintext = decrypt_text_cbc(package, key)
            _output_result(plaintext, args.output)
            return 0

        raise DesError("Невідома команда.")
    except (DesError, OSError) as error:
        print(f"Помилка: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
