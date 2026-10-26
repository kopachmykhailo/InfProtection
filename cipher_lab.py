
import argparse
import re
import sys
import unicodedata
from pathlib import Path


def configure_console_encoding():
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


configure_console_encoding()

ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
M = len(ALPHABET)
ALPHABET_UK = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
ALPHABET_LAT = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"


def prepare(text):
    return unicodedata.normalize("NFC", str(text or "")).upper()


def validate_keyword(key):
    key = prepare(key)
    if not key or any(ch not in ALPHABET for ch in key):
        raise ValueError("Ключ має містити лише українські літери.")
    return key


def alphabet_for(language):
    language = prepare(language).strip()
    if language in {"UK", "UA", "UKRAINIAN", "УКРАЇНСЬКИЙ"}:
        return ALPHABET_UK + "012"
    if language in {"LAT", "LATIN", "EN", "ENGLISH", "ЛАТИНСЬКИЙ"}:
        return ALPHABET_LAT + "0123456789"
    raise ValueError("Мова має бути 'uk' або 'lat'.")


def gronsfeld_alphabet(language):
    language = prepare(language).strip()
    if language in {"UK", "UA", "UKRAINIAN", "УКРАЇНСЬКИЙ"}:
        return ALPHABET_UK
    if language in {"LAT", "LATIN", "EN", "ENGLISH", "ЛАТИНСЬКИЙ"}:
        return ALPHABET_LAT
    raise ValueError("Мова має бути 'uk' або 'lat'.")


def build_square(keyword, language="uk"):
    base = list(alphabet_for(language))
    key = prepare(keyword)
    if not key or any(ch not in base for ch in key):
        raise ValueError("Ключове слово має містити лише символи вибраного алфавіту.")

    unique = []
    seen = set()
    for ch in key:
        if ch in base and ch not in seen:
            unique.append(ch)
            seen.add(ch)
    for ch in base:
        if ch not in seen:
            unique.append(ch)
            seen.add(ch)

    if len(unique) != 36:
        raise ValueError("Квадрат Полібія має містити рівно 36 унікальних символів.")

    return [unique[i:i + 6] for i in range(0, 36, 6)]


def format_square(square):
    lines = ["   " + " ".join(str(index) for index in range(1, 7))]
    lines.extend(
        f"{row_index}  " + " ".join(row)
        for row_index, row in enumerate(square, start=1)
    )
    return "\n".join(lines)


def square_lookup(square):
    direct = {}
    inverse = {}
    for row_index, row in enumerate(square):
        for col_index, symbol in enumerate(row):
            if symbol in direct:
                raise ValueError("Квадрат містить повторювані символи.")
            direct[symbol] = (row_index + 1, col_index + 1)
            inverse[(row_index + 1, col_index + 1)] = symbol
    return direct, inverse


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


def polybius_coordinates_encrypt(text, keyword, language="uk"):
    square = build_square(keyword, language)
    direct, _ = square_lookup(square)
    prepared = prepare(text)
    tokens = []

    for ch in prepared:
        if ch not in direct:
            raise ValueError(f"Символ '{ch}' не входить у квадрат Полібія.")
        row, col = direct[ch]
        tokens.append(f"{row}{col}")

    return " ".join(tokens)


def polybius_coordinates_decrypt(ciphertext, keyword, language="uk"):
    square = build_square(keyword, language)
    _, inverse = square_lookup(square)
    prepared = prepare(ciphertext).strip()
    if not prepared:
        return ""

    result = []
    for token in re.split(r"\s+", prepared):
        if len(token) != 2 or not token.isdigit():
            raise ValueError("Координатний шифротекст містить некоректні токени.")
        row, col = int(token[0]), int(token[1])
        if not (1 <= row <= 6 and 1 <= col <= 6):
            raise ValueError("Кожне значення координати має бути в межах 1..6.")
        if (row, col) not in inverse:
            raise ValueError(f"Координата {token} не існує в квадраті.")
        result.append(inverse[(row, col)])

    return "".join(result)


def polybius_row_shift_encrypt(text, keyword, language="uk"):
    square = build_square(keyword, language)
    direct, _ = square_lookup(square)
    prepared = prepare(text)
    result = []

    for ch in prepared:
        if ch in direct:
            row, col = direct[ch]
            next_row = ((row % 6) + 1)
            result.append(square[next_row - 1][col - 1])
        else:
            result.append(ch)

    return "".join(result)


def polybius_row_shift_decrypt(text, keyword, language="uk"):
    square = build_square(keyword, language)
    direct, _ = square_lookup(square)
    prepared = prepare(text)
    result = []

    for ch in prepared:
        if ch in direct:
            row, col = direct[ch]
            prev_row = ((row - 2) % 6) + 1
            result.append(square[prev_row - 1][col - 1])
        else:
            result.append(ch)

    return "".join(result)


def validate_gronsfeld_key(key):
    key = str(key)
    if not key or not key.isdigit() or all(digit == "0" for digit in key):
        raise ValueError("Цифровий ключ має бути непорожнім, містити лише цифри та мати хоча б одну ненульову цифру.")
    return key


def gronsfeld_encrypt(text, key, language="uk"):
    alphabet = gronsfeld_alphabet(language)
    key = validate_gronsfeld_key(key)
    prepared = prepare(text)
    result = []
    key_position = 0

    for ch in prepared:
        if ch in alphabet:
            index = alphabet.index(ch)
            shift = int(key[key_position % len(key)])
            result.append(alphabet[(index + shift) % len(alphabet)])
            key_position += 1
        else:
            result.append(ch)

    return "".join(result)


def gronsfeld_decrypt(text, key, language="uk"):
    alphabet = gronsfeld_alphabet(language)
    key = validate_gronsfeld_key(key)
    prepared = prepare(text)
    result = []
    key_position = 0

    for ch in prepared:
        if ch in alphabet:
            index = alphabet.index(ch)
            shift = int(key[key_position % len(key)])
            result.append(alphabet[(index - shift) % len(alphabet)])
            key_position += 1
        else:
            result.append(ch)

    return "".join(result)


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
        description="Лабораторна робота 1/2: навчальні шифри"
    )
    parser.add_argument("operation", choices=["encrypt", "decrypt", "square"])
    parser.add_argument(
        "--algorithm",
        choices=[
            "substitution", "vigenere", "block", "column",
            "polybius", "coordinates", "row_shift", "row-shift",
            "polybius_coordinates", "polybius_row_shift", "gronsfeld"
        ]
    )
    parser.add_argument("--mode", choices=["coordinates", "row_shift", "row-shift"], default=None)
    parser.add_argument("--lang", "--language", default="uk")
    parser.add_argument("--key")
    parser.add_argument("--text")
    parser.add_argument("--input")
    parser.add_argument("--output")
    parser.add_argument("--padding", type=int, default=0)
    args = parser.parse_args()

    try:
        if args.operation == "square":
            if args.key is None:
                raise ValueError("Для побудови квадрата вкажіть ключ через --key.")
            result = format_square(build_square(args.key, args.lang))
            if args.output:
                write_text(args.output, result)
            print(result)
            return 0

        if args.algorithm is None:
            raise ValueError("Для шифрування або розшифрування вкажіть --algorithm.")
        if args.key is None:
            raise ValueError("Для шифрування або розшифрування вкажіть --key.")

        if args.input:
            text = read_text(args.input)
        elif args.text is not None:
            text = args.text
        else:
            text = input("Введіть текст: ")

        algorithm = args.algorithm
        if algorithm in {"polybius", "coordinates", "polybius_coordinates"}:
            algorithm = "coordinates"
        elif algorithm in {"row_shift", "row-shift", "polybius_row_shift"}:
            algorithm = "row_shift"

        if algorithm == "substitution":
            if args.operation == "encrypt":
                result = substitution_encrypt(text, args.key)
            else:
                result = substitution_decrypt(text, args.key)

        elif algorithm == "vigenere":
            if args.operation == "encrypt":
                result = vigenere_encrypt(text, args.key)
            else:
                result = vigenere_decrypt(text, args.key)

        elif algorithm == "block":
            key = parse_key(args.key)
            if args.operation == "encrypt":
                result = block_encrypt(text, key)
            else:
                result = block_decrypt(text, key)

        elif algorithm == "column":
            key = parse_key(args.key)
            if args.operation == "encrypt":
                result, padding = column_encrypt(text, key)
                print(f"Кількість доповнень: {padding}")
            else:
                result = column_decrypt(text, key, args.padding)

        elif algorithm == "coordinates":
            if args.operation == "encrypt":
                result = polybius_coordinates_encrypt(text, args.key, args.lang)
            else:
                result = polybius_coordinates_decrypt(text, args.key, args.lang)

        elif algorithm == "row_shift":
            if args.operation == "encrypt":
                result = polybius_row_shift_encrypt(text, args.key, args.lang)
            else:
                result = polybius_row_shift_decrypt(text, args.key, args.lang)

        elif algorithm == "gronsfeld":
            if args.operation == "encrypt":
                result = gronsfeld_encrypt(text, args.key, args.lang)
            else:
                result = gronsfeld_decrypt(text, args.key, args.lang)

        else:
            raise ValueError(f"Непідтримуваний алгоритм: {args.algorithm}")

        if args.output:
            write_text(args.output, result)

        print("Результат:", result)
        return 0

    except (ValueError, OSError) as error:
        print(f"Помилка: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
