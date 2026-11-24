import base64
import binascii
import secrets


IP = (
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
)

IP_INV = (
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
)

E = (
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
)

P = (
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
)

PC1 = (
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
)

PC2 = (
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
)

LEFT_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

S_BOXES = (
    (
        (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
        (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
        (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
        (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    ),
    (
        (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
        (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
        (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
        (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    ),
    (
        (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
        (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
        (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
        (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    ),
    (
        (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
        (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
        (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
        (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    ),
    (
        (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
        (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
        (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
        (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    ),
    (
        (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
        (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
        (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
        (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    ),
    (
        (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
        (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
        (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
        (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    ),
    (
        (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
        (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
        (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
        (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
    ),
)

WEAK_KEYS = {
    bytes.fromhex(value)
    for value in (
        "0101010101010101",
        "FEFEFEFEFEFEFEFE",
        "E0E0E0E0F1F1F1F1",
        "1F1F1F1F0E0E0E0E",
    )
}

SEMI_WEAK_KEYS = {
    bytes.fromhex(value)
    for value in (
        "01FE01FE01FE01FE",
        "FE01FE01FE01FE01",
        "1FE01FE00EF10EF1",
        "E01FE01FF10EF10E",
        "01E001E001F101F1",
        "E001E001F101F101",
        "1FFE1FFE0EFE0EFE",
        "FE1FFE1FFE0EFE0E",
        "011F011F010E010E",
        "1F011F010E010E01",
        "E0FEE0FEF1FEF1FE",
        "FEE0FEE0FEF1FEF1",
    )
}

FORBIDDEN_KEYS = WEAK_KEYS | SEMI_WEAK_KEYS


class DesError(ValueError):
    pass


def _normalize_hex(value, expected_bytes, label):
    if not isinstance(value, str):
        raise DesError(f"{label} має бути рядком шістнадцяткових символів.")
    compact = value.strip()
    if " " in compact or "\t" in compact or "\n" in compact or "\r" in compact:
        raise DesError(f"{label} не повинен містити пробілів або розділювачів.")
    if len(compact) != expected_bytes * 2:
        raise DesError(
            f"{label} має містити рівно {expected_bytes * 2} шістнадцяткових символів."
        )
    try:
        int(compact, 16)
        return bytes.fromhex(compact)
    except ValueError as error:
        raise DesError(f"{label} містить некоректні шістнадцяткові символи.") from error


def decode_hex_block(value):
    return _normalize_hex(value, 8, "HEX-блок")


def _has_odd_parity(byte_value):
    return (byte_value.bit_count() % 2) == 1


def decode_des_key(value):
    key = _normalize_hex(value, 8, "HEX-ключ")
    if any(not _has_odd_parity(byte) for byte in key):
        raise DesError("Кожен байт DES-ключа має мати непарну парність.")
    if key in FORBIDDEN_KEYS:
        raise DesError("DES-ключ належить до відомих слабких або напівслабких ключів.")
    return key


def bytes_to_bits(data):
    bits = []
    for byte in data:
        for index in range(7, -1, -1):
            bits.append((byte >> index) & 1)
    return bits


def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise DesError("Кількість бітів має бути кратною 8.")
    result = bytearray()
    for index in range(0, len(bits), 8):
        value = 0
        for bit in bits[index:index + 8]:
            value = (value << 1) | (1 if bit else 0)
        result.append(value)
    return bytes(result)


def bits_to_hex(bits):
    return bits_to_bytes(bits).hex().upper()


def permute(bits, table):
    return [bits[position - 1] for position in table]


def left_shift(bits, count):
    return bits[count:] + bits[:count]


def xor_bits(left, right):
    if len(left) != len(right):
        raise DesError("Послідовності для XOR мають мати однакову довжину.")
    return [a ^ b for a, b in zip(left, right)]


def make_subkeys(key_bytes):
    key_bits = bytes_to_bits(key_bytes)
    permuted = permute(key_bits, PC1)
    left = permuted[:28]
    right = permuted[28:]
    subkeys = []
    for shift in LEFT_SHIFTS:
        left = left_shift(left, shift)
        right = left_shift(right, shift)
        subkeys.append(permute(left + right, PC2))
    return subkeys


def _sbox_substitution(bits48):
    output = []
    for index, sbox in enumerate(S_BOXES):
        chunk = bits48[index * 6:(index + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        column = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        value = sbox[row][column]
        output.extend([(value >> shift) & 1 for shift in range(3, -1, -1)])
    return output


def feistel_function(right32, subkey48):
    expanded = permute(right32, E)
    mixed = xor_bits(expanded, subkey48)
    substituted = _sbox_substitution(mixed)
    return permute(substituted, P)


def des_block(block8, key8, decrypt=False, trace=False):
    if not isinstance(block8, (bytes, bytearray)) or len(block8) != 8:
        raise DesError("DES працює з блоком рівно 8 байтів.")
    if not isinstance(key8, (bytes, bytearray)) or len(key8) != 8:
        raise DesError("DES працює з ключем рівно 8 байтів.")
    subkeys = make_subkeys(key8)
    if decrypt:
        subkeys = list(reversed(subkeys))
    initial = permute(bytes_to_bits(block8), IP)
    trace_data = None
    if trace:
        trace_data = {
            "after_ip": bits_to_hex(initial),
            "k1": bits_to_hex(make_subkeys(key8)[0]),
            "rounds": [],
        }
    left = initial[:32]
    right = initial[32:]
    for round_index, subkey in enumerate(subkeys, start=1):
        previous_left = left
        left = right
        right = xor_bits(previous_left, feistel_function(right, subkey))
        if trace:
            trace_data["rounds"].append(
                {
                    "round": round_index,
                    "l": bits_to_hex(left),
                    "r": bits_to_hex(right),
                    "subkey": bits_to_hex(subkey),
                }
            )
    preoutput = right + left
    result_bits = permute(preoutput, IP_INV)
    result = bits_to_bytes(result_bits)
    if trace:
        trace_data["preoutput"] = bits_to_hex(preoutput)
        trace_data["output"] = bits_to_hex(result_bits)
        return result, trace_data
    return result


def format_block_trace(trace_data, decrypt=False):
    mode = "розшифрування" if decrypt else "шифрування"
    lines = [
        f"Трасування DES-блока ({mode})",
        f"Після IP: {trace_data['after_ip']}",
        f"K1: {trace_data['k1']}",
    ]
    for item in trace_data["rounds"]:
        lines.append(
            f"Раунд {item['round']:02d}: L={item['l']} R={item['r']} K={item['subkey']}"
        )
    lines.append(f"R16||L16: {trace_data['preoutput']}")
    lines.append(f"Після IP^-1: {trace_data['output']}")
    return "\n".join(lines)


def pkcs7_pad(data, block_size=8):
    if block_size <= 0 or block_size > 255:
        raise DesError("Некоректний розмір блока для PKCS#7.")
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data, block_size=8):
    if not data or len(data) % block_size != 0:
        raise DesError("Довжина даних після CBC має бути кратною розміру блока.")
    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise DesError("Некоректне доповнення PKCS#7.")
    padding = data[-padding_length:]
    if any(byte != padding_length for byte in padding):
        raise DesError("Некоректне доповнення PKCS#7.")
    return data[:-padding_length]


def decode_base64_package(value):
    if not isinstance(value, str):
        raise DesError("Base64-пакет має бути рядком.")
    compact = "".join(value.split())
    if not compact:
        raise DesError("Base64-пакет не може бути порожнім.")
    try:
        encoded = compact.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise DesError("Пакет містить некоректний Base64.") from error
    if base64.b64encode(decoded) != encoded:
        raise DesError("Пакет містить некоректний Base64.")
    if len(decoded) < 16 or (len(decoded) - 8) % 8 != 0:
        raise DesError("Base64-пакет має містити IV та шифротекст, кратний 8 байтам.")
    return decoded[:8], decoded[8:]


def encode_base64_package(iv, ciphertext):
    if len(iv) != 8:
        raise DesError("IV має містити рівно 8 байтів.")
    if not ciphertext or len(ciphertext) % 8 != 0:
        raise DesError("Шифротекст CBC має бути непорожнім і кратним 8 байтам.")
    return base64.b64encode(iv + ciphertext).decode("ascii")


def generate_iv():
    return secrets.token_bytes(8)


def encrypt_text_cbc(plaintext, key_bytes, iv=None):
    if not isinstance(plaintext, str):
        raise DesError("Відкритий текст має бути рядком.")
    if iv is None:
        iv = generate_iv()
    elif not isinstance(iv, (bytes, bytearray)) or len(iv) != 8:
        raise DesError("IV має містити рівно 8 байтів.")
    data = pkcs7_pad(plaintext.encode("utf-8"), 8)
    previous = bytes(iv)
    ciphertext_blocks = []
    for index in range(0, len(data), 8):
        block = bytes(
            value ^ previous[offset]
            for offset, value in enumerate(data[index:index + 8])
        )
        encrypted = des_block(block, key_bytes, decrypt=False)
        ciphertext_blocks.append(encrypted)
        previous = encrypted
    return encode_base64_package(bytes(iv), b"".join(ciphertext_blocks))


def decrypt_text_cbc(package_b64, key_bytes):
    iv, ciphertext = decode_base64_package(package_b64)
    previous = iv
    plaintext_blocks = []
    for index in range(0, len(ciphertext), 8):
        block = ciphertext[index:index + 8]
        decrypted = des_block(block, key_bytes, decrypt=True)
        plaintext_block = bytes(
            value ^ previous[offset] for offset, value in enumerate(decrypted)
        )
        plaintext_blocks.append(plaintext_block)
        previous = block
    padded = b"".join(plaintext_blocks)
    try:
        data = pkcs7_unpad(padded, 8)
        return data.decode("utf-8", errors="strict")
    except (DesError, UnicodeDecodeError) as error:
        raise DesError("Не вдалося розшифрувати пакет: некоректний формат або ключ.") from error
