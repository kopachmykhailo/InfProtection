
import argparse
import sys
import unicodedata
from pathlib import Path

ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
M = len(ALPHABET)


def prepare(text):
    return unicodedata.normalize("NFC", text).upper()


def validate_keyword(key):
    key = prepare(key)
    if not key or any(ch not in ALPHABET for ch in key):
        raise ValueError("Ключ має містити лише українські літери.")
    return key


def substitution_alphabet(key):
    key = validate_keyword(key)
    result = []

    for ch in key + ALPHABET:
        if ch not in result:
            result.append(ch)

    return "".join(result)


def substitution_encrypt(text, key):
    table = substitution_alphabet(key)
    text = prepare(text)
    return "".join(
        table[ALPHABET.index(ch)] if ch in ALPHABET else ch
        for ch in text
    )


def substitution_decrypt(text, key):
    table = substitution_alphabet(key)
    inverse = {table[i]: ALPHABET[i] for i in range(M)}
    text = prepare(text)

    return "".join(inverse.get(ch, ch) for ch in text)


def vigenere_encrypt(text, key):
    key = validate_keyword(key)
    text = prepare(text)
    result = []
    position = 0

    for ch in text:
        if ch in ALPHABET:
            p = ALPHABET.index(ch)
            k = ALPHABET.index(key[position % len(key)])
            result.append(ALPHABET[(p + k) % M])
            position += 1
        else:
            result.append(ch)

    return "".join(result)


def vigenere_decrypt(text, key):
    key = validate_keyword(key)
    text = prepare(text)
    result = []
    position = 0

    for ch in text:
        if ch in ALPHABET:
            c = ALPHABET.index(ch)
            k = ALPHABET.index(key[position % len(key)])
            result.append(ALPHABET[(c - k) % M])
            position += 1
        else:
            result.append(ch)

    return "".join(result)


def validate_permutation(key):
    try:
        key = tuple(int(x) for x in key)
    except (TypeError, ValueError):
        raise ValueError("Ключ має містити цілі числа.") from None

    n = len(key)
    if n == 0 or set(key) != set(range(1, n + 1)):
        raise ValueError(
            f"Перестановка має містити числа від 1 до {n} без повторів."
        )

    return key


def block_encrypt(text, key):
    key = validate_permutation(key)
    text = prepare(text)
    n = len(key)
    result = []

    for start in range(0, len(text), n):
        block = text[start:start + n]

        if len(block) < n:
            result.append(block)
        else:
            result.append("".join(block[i - 1] for i in key))

    return "".join(result)


def block_decrypt(text, key):
    key = validate_permutation(key)
    text = prepare(text)
    n = len(key)
    inverse = [0] * n

    for output_pos, input_pos in enumerate(key, start=1):
        inverse[input_pos - 1] = output_pos

    result = []

    for start in range(0, len(text), n):
        block = text[start:start + n]

        if len(block) < n:
            result.append(block)
        else:
            result.append("".join(block[i - 1] for i in inverse))

    return "".join(result)


def column_encrypt(text, key):
    key = validate_permutation(key)
    text = prepare(text)
    width = len(key)
    padding = (-len(text)) % width
    text += "Х" * padding

    rows = [
        text[i:i + width]
        for i in range(0, len(text), width)
    ]

    result = "".join(
        row[column - 1]
        for column in key
        for row in rows
    )

    return result, padding


def column_decrypt(text, key, padding=0):
    key = validate_permutation(key)
    text = prepare(text)
    width = len(key)

    if not isinstance(padding, int) or not 0 <= padding < width:
        raise ValueError(
            "Кількість доповнень має бути від 0 до ширини ключа - 1."
        )

    if len(text) % width:
        raise ValueError(
            "Довжина шифротексту має ділитися на довжину ключа."
        )

    rows_count = len(text) // width
    grid = [[""] * width for _ in range(rows_count)]
    position = 0

    for column in key:
        for row in range(rows_count):
            grid[row][column - 1] = text[position]
            position += 1

    result = "".join("".join(row) for row in grid)

    if padding:
        result = result[:-padding]

    return result


def read_text(path):
    return Path(path).read_text(encoding="utf-8")


def write_text(path, text):
    Path(path).write_text(text, encoding="utf-8")


def parse_key(value):
    try:
        return tuple(int(x.strip()) for x in value.split(","))
    except ValueError:
        raise ValueError(
            "Для перестановки введіть числа через кому: 3,2,5,1,4."
        ) from None


def main():
    parser = argparse.ArgumentParser(
        description="Лабораторна робота №1: навчальні шифри"
    )
    parser.add_argument("operation", choices=["encrypt", "decrypt"])
    parser.add_argument(
        "--algorithm",
        required=True,
        choices=["substitution", "vigenere", "block", "column"]
    )
    parser.add_argument("--key", required=True)
    parser.add_argument("--text")
    parser.add_argument("--input")
    parser.add_argument("--output")
    parser.add_argument("--padding", type=int, default=0)
    args = parser.parse_args()

    try:
        if args.input:
            text = read_text(args.input)
        elif args.text is not None:
            text = args.text
        else:
            text = input("Введіть текст: ")

        if args.algorithm == "substitution":
            if args.operation == "encrypt":
                result = substitution_encrypt(text, args.key)
            else:
                result = substitution_decrypt(text, args.key)

        elif args.algorithm == "vigenere":
            if args.operation == "encrypt":
                result = vigenere_encrypt(text, args.key)
            else:
                result = vigenere_decrypt(text, args.key)

        elif args.algorithm == "block":
            key = parse_key(args.key)
            if args.operation == "encrypt":
                result = block_encrypt(text, key)
            else:
                result = block_decrypt(text, key)

        else:
            key = parse_key(args.key)
            if args.operation == "encrypt":
                result, padding = column_encrypt(text, key)
                print(f"Кількість доповнень: {padding}")
            else:
                result = column_decrypt(text, key, args.padding)

        if args.output:
            write_text(args.output, result)

        print("Результат:", result)
        return 0

    except (ValueError, OSError) as error:
        print(f"Помилка: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
