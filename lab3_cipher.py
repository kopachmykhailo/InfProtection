import base64
import binascii
import secrets
import unicodedata


LATIN_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
SQUARE_SIZE = 5


def _normalize_latin(text):
    return unicodedata.normalize("NFC", text).upper().replace("J", "I")


def build_latin_square(keyword):
    key = _normalize_latin(keyword)
    if not key or any(symbol not in LATIN_ALPHABET for symbol in key):
        raise ValueError("Ключ має містити лише латинські літери A-Z.")

    symbols = list(dict.fromkeys(key))
    symbols.extend(symbol for symbol in LATIN_ALPHABET if symbol not in symbols)
    if len(symbols) != SQUARE_SIZE * SQUARE_SIZE:
        raise ValueError("Квадрат має містити рівно 25 унікальних символів.")
    return [
        symbols[index:index + SQUARE_SIZE]
        for index in range(0, len(symbols), SQUARE_SIZE)
    ]


def format_latin_square(square):
    if (
        len(square) != SQUARE_SIZE
        or any(len(row) != SQUARE_SIZE for row in square)
        or len({symbol for row in square for symbol in row}) != 25
        or set(symbol for row in square for symbol in row) != set(LATIN_ALPHABET)
    ):
        raise ValueError("Очікується квадрат 5x5 з усіх 25 літер алфавіту.")
    lines = ["   " + " ".join(str(index) for index in range(1, 6))]
    lines.extend(
        f"{row_index}  " + " ".join(row)
        for row_index, row in enumerate(square, start=1)
    )
    return "\n".join(lines)


def _positions(square):
    return {
        symbol: (row_index, column_index)
        for row_index, row in enumerate(square)
        for column_index, symbol in enumerate(row)
    }


def prepare_bigrams(text, strict=False):
    normalized = _normalize_latin(text)
    if strict and any(symbol not in LATIN_ALPHABET for symbol in normalized):
        raise ValueError("Текст містить символи поза латинським алфавітом A-Z.")
    letters = [symbol for symbol in normalized if symbol in LATIN_ALPHABET]
    if not letters:
        raise ValueError("Після підготовки не залишилося жодної латинської літери.")

    prepared = []
    index = 0
    while index < len(letters):
        first = letters[index]
        if index + 1 == len(letters):
            prepared.extend((first, "Q" if first == "X" else "X"))
            index += 1
        elif letters[index + 1] == first:
            prepared.extend((first, "Q" if first == "X" else "X"))
            index += 1
        else:
            prepared.extend((first, letters[index + 1]))
            index += 2
    return "".join(prepared)


def format_bigrams(text):
    if len(text) % 2:
        raise ValueError("Підготовлений текст біграм має парну довжину.")
    return " ".join(text[index:index + 2] for index in range(0, len(text), 2))


def _validate_ciphertext(ciphertext):
    normalized = unicodedata.normalize("NFC", ciphertext).upper()
    if any(symbol not in LATIN_ALPHABET and not symbol.isspace() for symbol in normalized):
        raise ValueError("Шифротекст може містити лише літери A-Z та пробіли між біграмами.")
    letters = "".join(symbol for symbol in normalized if not symbol.isspace())
    if not letters:
        raise ValueError("Шифротекст не може бути порожнім.")
    if len(letters) % 2:
        raise ValueError("Довжина біграмного шифротексту має бути парною.")
    return letters


def _playfair_pair(pair, square, positions, direction):
    first_row, first_column = positions[pair[0]]
    second_row, second_column = positions[pair[1]]
    if first_row == second_row:
        return (
            square[first_row][(first_column + direction) % SQUARE_SIZE]
            + square[second_row][(second_column + direction) % SQUARE_SIZE]
        )
    if first_column == second_column:
        return (
            square[(first_row + direction) % SQUARE_SIZE][first_column]
            + square[(second_row + direction) % SQUARE_SIZE][second_column]
        )
    return square[first_row][second_column] + square[second_row][first_column]


def playfair_encrypt(text, keyword, strict=False):
    square = build_latin_square(keyword)
    positions = _positions(square)
    prepared = prepare_bigrams(text, strict=strict)
    return "".join(
        _playfair_pair(prepared[index:index + 2], square, positions, 1)
        for index in range(0, len(prepared), 2)
    )


def playfair_decrypt(ciphertext, keyword):
    square = build_latin_square(keyword)
    positions = _positions(square)
    prepared = _validate_ciphertext(ciphertext)
    return "".join(
        _playfair_pair(prepared[index:index + 2], square, positions, -1)
        for index in range(0, len(prepared), 2)
    )


def double_square_encrypt(text, left_keyword, right_keyword, strict=False):
    left = build_latin_square(left_keyword)
    right = build_latin_square(right_keyword)
    left_positions = _positions(left)
    right_positions = _positions(right)
    prepared = prepare_bigrams(text, strict=strict)
    result = []

    for index in range(0, len(prepared), 2):
        first_row, first_column = left_positions[prepared[index]]
        second_row, second_column = right_positions[prepared[index + 1]]
        if first_row == second_row:
            result.append(right[first_row][first_column])
            result.append(left[second_row][second_column])
        else:
            result.append(right[first_row][second_column])
            result.append(left[second_row][first_column])
    return "".join(result)


def double_square_decrypt(ciphertext, left_keyword, right_keyword):
    left = build_latin_square(left_keyword)
    right = build_latin_square(right_keyword)
    left_positions = _positions(left)
    right_positions = _positions(right)
    prepared = _validate_ciphertext(ciphertext)
    result = []

    for index in range(0, len(prepared), 2):
        first_row, first_column = right_positions[prepared[index]]
        second_row, second_column = left_positions[prepared[index + 1]]
        if first_row == second_row:
            result.append(left[first_row][first_column])
            result.append(right[second_row][second_column])
        else:
            result.append(left[first_row][second_column])
            result.append(right[second_row][first_column])
    return "".join(result)


def xor_bytes(data, key):
    if not isinstance(data, bytes) or not isinstance(key, bytes):
        raise TypeError("Повідомлення та ключ мають бути bytes.")
    if len(data) != len(key):
        raise ValueError("Довжина ключа має дорівнювати довжині даних у байтах.")
    return bytes(value ^ key[index] for index, value in enumerate(data))


def vernam_encrypt_with_key(message, key):
    if not isinstance(message, str):
        raise TypeError("Повідомлення Vernam має бути рядком.")
    ciphertext = xor_bytes(message.encode("utf-8"), key)
    return (
        base64.b64encode(ciphertext).decode("ascii"),
        base64.b64encode(key).decode("ascii"),
    )


def vernam_encrypt(message):
    if not isinstance(message, str):
        raise TypeError("Повідомлення Vernam має бути рядком.")
    message_bytes = message.encode("utf-8")
    key = secrets.token_bytes(len(message_bytes))
    ciphertext = xor_bytes(message_bytes, key)
    return (
        base64.b64encode(ciphertext).decode("ascii"),
        base64.b64encode(key).decode("ascii"),
    )


def _decode_base64(value, label):
    if not isinstance(value, str):
        raise TypeError(f"{label} має бути рядком Base64.")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ValueError(f"{label} містить некоректний Base64.") from None
    if base64.b64encode(decoded) != encoded:
        raise ValueError(f"{label} містить некоректний Base64.")
    return decoded


def vernam_decrypt(ciphertext_b64, key_b64):
    ciphertext = _decode_base64(ciphertext_b64, "Шифротекст")
    key = _decode_base64(key_b64, "Ключ")
    plaintext = xor_bytes(ciphertext, key)
    try:
        return plaintext.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValueError("Результат Vernam не є коректним текстом UTF-8.") from None
