import argparse
import base64
import os
import secrets
import sys
import tempfile
from pathlib import Path

from lab3_cipher import (
    build_latin_square,
    double_square_decrypt,
    double_square_encrypt,
    format_bigrams,
    format_latin_square,
    playfair_decrypt,
    playfair_encrypt,
    prepare_bigrams,
    vernam_decrypt,
    vernam_encrypt,
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


def _read_utf8(path):
    return Path(path).read_bytes().decode("utf-8", errors="strict")


def _atomic_write_utf8(path, text):
    destination = Path(path)
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


def _validate_destinations(*paths):
    destinations = [Path(path).resolve() for path in paths if path]
    if len(set(destinations)) != len(destinations):
        raise ValueError("Файли результату та ключа мають мати різні шляхи.")
    for destination in destinations:
        if not destination.parent.is_dir():
            raise ValueError(f"Каталог для запису не існує: {destination.parent}")
        if destination.exists() and not destination.is_file():
            raise ValueError(f"Шлях результату не є файлом: {destination}")


def _text_from_args(args):
    if args.input:
        return _read_utf8(args.input)
    if args.text is not None:
        return args.text
    return sys.stdin.read()


def _key_from_args(args):
    if args.key_file:
        return _read_utf8(args.key_file).strip()
    return args.key_b64


def _make_parser():
    parser = argparse.ArgumentParser(
        description="Лабораторна робота 3: Playfair, два квадрати та Vernam XOR."
    )
    parser.add_argument(
        "operation",
        choices=("encrypt", "decrypt", "square", "prepare", "keygen"),
        help="Операція; без --text або --input текст читається зі stdin.",
    )
    parser.add_argument(
        "--algorithm",
        choices=("playfair", "double", "vernam"),
        help="Алгоритм для encrypt або decrypt.",
    )
    parser.add_argument("--key", help="Ключ Playfair або лівого квадрата.")
    parser.add_argument("--right-key", help="Ключ правого квадрата.")
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument("--key-b64", help="Ключ Vernam у Base64 для decrypt.")
    key_group.add_argument("--key-file", help="Файл UTF-8 з ключем Vernam у Base64.")
    text_group = parser.add_mutually_exclusive_group()
    text_group.add_argument("--text", help="Текст; для навчальних прикладів.")
    text_group.add_argument("--input", help="Файл UTF-8 з текстом.")
    parser.add_argument("--output", help="Файл UTF-8 для результату.")
    parser.add_argument(
        "--key-output",
        help="Файл UTF-8 для випадкового ключа Vernam у Base64.",
    )
    parser.add_argument("--length", type=int, help="Довжина ключа для keygen у байтах.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Відхиляти сторонні символи у відкритому біграмному тексті.",
    )
    return parser


def main(argv=None):
    parser = _make_parser()
    args = parser.parse_args(argv)
    try:
        if args.operation == "keygen":
            if args.length is None or args.length < 0:
                raise ValueError("Для keygen вкажіть невід'ємну довжину через --length.")
            if (
                args.output
                or args.key_output
                or args.algorithm
                or args.key
                or args.right_key
                or args.key_b64
                or args.key_file
                or args.text is not None
                or args.input
                or args.strict
            ):
                raise ValueError("Для keygen використовуйте лише --length.")
            result = base64.b64encode(secrets.token_bytes(args.length)).decode("ascii")
            print(result)
            return 0

        if args.operation in {"square", "prepare"}:
            if (
                args.algorithm
                or args.key_b64
                or args.key_file
                or args.key_output
            ):
                raise ValueError("Ці параметри не застосовуються до вибраної операції.")
            if args.operation == "square":
                if args.strict:
                    raise ValueError("--strict не застосовується до square.")
                if args.key is None:
                    raise ValueError("Для square вкажіть --key.")
                left_square = build_latin_square(args.key)
                if args.right_key is None:
                    result = format_latin_square(left_square)
                else:
                    right_square = build_latin_square(args.right_key)
                    result = (
                        "Лівий квадрат:\n"
                        + format_latin_square(left_square)
                        + "\n\nПравий квадрат:\n"
                        + format_latin_square(right_square)
                    )
            else:
                if args.key or args.right_key:
                    raise ValueError("Для prepare ключ не потрібен.")
                result = format_bigrams(prepare_bigrams(_text_from_args(args), args.strict))
            if args.output:
                _validate_destinations(args.output)
                _atomic_write_utf8(args.output, result)
            else:
                print(result)
            return 0

        if args.algorithm is None:
            raise ValueError("Для encrypt або decrypt вкажіть --algorithm.")
        if args.operation == "encrypt" and (args.key_b64 or args.key_file):
            raise ValueError("Створюйте ключ Vernam через системний CSPRNG.")
        if args.operation == "decrypt" and args.key_output:
            raise ValueError("--key-output використовується лише для encrypt Vernam.")
        if args.algorithm == "playfair":
            if (
                args.key is None
                or args.right_key
                or args.key_output
                or args.key_b64
                or args.key_file
            ):
                raise ValueError("Playfair потребує лише ключ --key.")
            text = _text_from_args(args)
            result = (
                playfair_encrypt(text, args.key, strict=args.strict)
                if args.operation == "encrypt"
                else playfair_decrypt(text, args.key)
            )
            key_result = None
        elif args.algorithm == "double":
            if (
                args.key is None
                or args.right_key is None
                or args.key_output
                or args.key_b64
                or args.key_file
            ):
                raise ValueError("Два квадрати потребують --key та --right-key.")
            text = _text_from_args(args)
            result = (
                double_square_encrypt(
                    text, args.key, args.right_key, strict=args.strict
                )
                if args.operation == "encrypt"
                else double_square_decrypt(text, args.key, args.right_key)
            )
            key_result = None
        else:
            if args.key or args.right_key or args.strict:
                raise ValueError("Vernam не використовує ключі квадратів або --strict.")
            text = _text_from_args(args)
            if args.operation == "encrypt":
                result, key_result = vernam_encrypt(text)
            else:
                key_value = _key_from_args(args)
                if key_value is None:
                    raise ValueError("Для decrypt Vernam вкажіть --key-b64 або --key-file.")
                result = vernam_decrypt(text.strip(), key_value)
                key_result = None

        _validate_destinations(
            args.output,
            args.key_output if key_result is not None else None,
        )
        if args.output:
            _atomic_write_utf8(args.output, result)
        else:
            print(result)
        if key_result is not None:
            if args.key_output:
                _atomic_write_utf8(args.key_output, key_result)
            else:
                print(f"Ключ Vernam (Base64): {key_result}")
        return 0
    except (ValueError, OSError, UnicodeDecodeError) as error:
        print(f"Помилка: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
