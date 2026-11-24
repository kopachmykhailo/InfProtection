import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lab4_des import (
    E,
    IP,
    IP_INV,
    LEFT_SHIFTS,
    P,
    PC1,
    PC2,
    S_BOXES,
    DesError,
    bits_to_bytes,
    bytes_to_bits,
    decode_base64_package,
    decode_des_key,
    decode_hex_block,
    decrypt_text_cbc,
    des_block,
    encode_base64_package,
    encrypt_text_cbc,
    feistel_function,
    left_shift,
    make_subkeys,
    permute,
    pkcs7_pad,
    pkcs7_unpad,
    xor_bits,
)


ROOT = Path(__file__).resolve().parents[1]
CONTROL_KEY = "133457799BBCDFF1"
CONTROL_PLAINTEXT = "0123456789ABCDEF"
CONTROL_CIPHERTEXT = "85E813540F0AB405"


class Lab4ConstantTests(unittest.TestCase):
    def test_permutation_sizes_and_ranges(self):
        self.assertEqual(sorted(IP), list(range(1, 65)))
        self.assertEqual(sorted(IP_INV), list(range(1, 65)))
        self.assertEqual(sorted(P), list(range(1, 33)))
        self.assertEqual(sorted(PC1), [value for value in range(1, 65) if value % 8 != 0])
        self.assertEqual(len(IP), 64)
        self.assertEqual(len(IP_INV), 64)
        self.assertEqual(len(E), 48)
        self.assertEqual(len(P), 32)
        self.assertEqual(len(PC1), 56)
        self.assertEqual(len(PC2), 48)
        self.assertEqual(len(LEFT_SHIFTS), 16)
        self.assertTrue(all(1 <= value <= 64 for value in PC1))
        self.assertTrue(all(1 <= value <= 56 for value in PC2))
        self.assertTrue(all(1 <= value <= 32 for value in E))

    def test_ip_and_inverse_are_reversible(self):
        for value in range(256):
            block = bytes([value]) + bytes(range(7))
            bits = bytes_to_bits(block)
            restored = permute(permute(bits, IP), IP_INV)
            self.assertEqual(bits_to_bytes(restored), block)

    def test_sboxes_shape_and_values(self):
        self.assertEqual(len(S_BOXES), 8)
        for index, sbox in enumerate(S_BOXES, start=1):
            with self.subTest(sbox=index):
                self.assertEqual(len(sbox), 4)
                for row in sbox:
                    self.assertEqual(len(row), 16)
                    self.assertTrue(all(0 <= value <= 15 for value in row))

    def test_left_shift_schedule(self):
        self.assertEqual(LEFT_SHIFTS, (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1))
        bits = [1, 0, 1, 1] + [0] * 24
        self.assertEqual(left_shift(bits, 2), bits[2:] + bits[:2])


class Lab4KeyScheduleTests(unittest.TestCase):
    def test_control_key_generates_expected_k1(self):
        key = decode_des_key(CONTROL_KEY)
        subkeys = make_subkeys(key)
        self.assertEqual(len(subkeys), 16)
        self.assertTrue(all(len(subkey) == 48 for subkey in subkeys))
        self.assertEqual(bits_to_bytes(subkeys[0]).hex().upper(), "1B02EFFC7072".ljust(12, "0")[:12])
        # precise 48-bit hex check
        self.assertEqual(
            "".join(str(bit) for bit in subkeys[0]),
            bin(int("1B02EFFC7072", 16))[2:].zfill(48),
        )

    def test_key_parity_and_forbidden_keys(self):
        with self.assertRaises(DesError):
            decode_des_key("133457799BBCDFF0")  # bad parity in last byte
        for weak in (
            "0101010101010101",
            "FEFEFEFEFEFEFEFE",
            "E0E0E0E0F1F1F1F1",
            "1F1F1F1F0E0E0E0E",
            "01FE01FE01FE01FE",
            "FE01FE01FE01FE01",
        ):
            with self.subTest(weak=weak):
                with self.assertRaises(DesError):
                    decode_des_key(weak)

    def test_key_format_validation(self):
        for value in ("", "1234", "ZZ3457799BBCDFF1", "133457799BBCDFF", "1334 57799BBCDFF1"):
            with self.subTest(value=value):
                with self.assertRaises(DesError):
                    decode_des_key(value)


class Lab4BlockTests(unittest.TestCase):
    def test_control_vector_encrypt_decrypt(self):
        key = decode_des_key(CONTROL_KEY)
        block = decode_hex_block(CONTROL_PLAINTEXT)
        encrypted = des_block(block, key, decrypt=False)
        self.assertEqual(encrypted.hex().upper(), CONTROL_CIPHERTEXT)
        decrypted = des_block(encrypted, key, decrypt=True)
        self.assertEqual(decrypted.hex().upper(), CONTROL_PLAINTEXT)

    def test_trace_contains_control_checkpoints(self):
        key = decode_des_key(CONTROL_KEY)
        block = decode_hex_block(CONTROL_PLAINTEXT)
        result, trace = des_block(block, key, decrypt=False, trace=True)
        self.assertEqual(result.hex().upper(), CONTROL_CIPHERTEXT)
        self.assertEqual(trace["after_ip"], "CC00CCFFF0AAF0AA")
        self.assertEqual(trace["k1"], "1B02EFFC7072")
        self.assertEqual(len(trace["rounds"]), 16)

    def test_round_trip_random_blocks(self):
        key = decode_des_key(CONTROL_KEY)
        for seed in range(20):
            block = bytes((seed * 31 + index * 17) % 256 for index in range(8))
            encrypted = des_block(block, key, decrypt=False)
            decrypted = des_block(encrypted, key, decrypt=True)
            self.assertEqual(decrypted, block)

    def test_block_input_validation(self):
        key = decode_des_key(CONTROL_KEY)
        with self.assertRaises(DesError):
            decode_hex_block("0123456789ABCDE")
        with self.assertRaises(DesError):
            decode_hex_block("0123456789ABCDEG")
        with self.assertRaises(DesError):
            des_block(b"short", key)


class Lab4PaddingAndCbcTests(unittest.TestCase):
    def test_pkcs7_padding_lengths(self):
        cases = {
            b"": bytes([8] * 8),
            b"A": b"A" + bytes([7] * 7),
            b"ABCDEFG": b"ABCDEFG" + b"\x01",
            b"ABCDEFGH": b"ABCDEFGH" + bytes([8] * 8),
            b"ABCDEFGHI": b"ABCDEFGHI" + bytes([7] * 7),
        }
        for data, expected in cases.items():
            with self.subTest(length=len(data)):
                padded = pkcs7_pad(data, 8)
                self.assertEqual(padded, expected)
                self.assertEqual(len(padded) % 8, 0)
                self.assertEqual(pkcs7_unpad(padded, 8), data)

    def test_pkcs7_rejects_invalid_padding(self):
        for padded in (
            b"ABCDEFGH\x00",
            b"ABCDEFGH\x09",
            b"ABCDEFGH\x02\x03",
            b"ABC",
        ):
            with self.subTest(padded=padded):
                with self.assertRaises(DesError):
                    pkcs7_unpad(padded, 8)

    def test_cbc_vectors(self):
        key = decode_des_key(CONTROL_KEY)
        iv = bytes.fromhex("0102030405060708")
        self.assertEqual(
            encrypt_text_cbc("HELLO", key, iv=iv),
            "AQIDBAUGBwhZhXOTulwNWA==",
        )
        self.assertEqual(
            encrypt_text_cbc("Привіт", key, iv=iv),
            "AQIDBAUGBwjTC3MCWWogVVRlDZmRU1a9",
        )
        self.assertEqual(
            decrypt_text_cbc("AQIDBAUGBwhZhXOTulwNWA==", key),
            "HELLO",
        )
        self.assertEqual(
            decrypt_text_cbc("AQIDBAUGBwjTC3MCWWogVVRlDZmRU1a9", key),
            "Привіт",
        )

    def test_cbc_round_trip_unicode_and_empty(self):
        key = decode_des_key(CONTROL_KEY)
        messages = ["", "Привіт", "🙂", "e\u0301", "line1\nline2", "A" * 100]
        for message in messages:
            with self.subTest(message=message):
                package = encrypt_text_cbc(message, key)
                self.assertEqual(decrypt_text_cbc(package, key), message)

    def test_random_iv_produces_different_packages(self):
        key = decode_des_key(CONTROL_KEY)
        packages = {encrypt_text_cbc("same", key) for _ in range(5)}
        self.assertGreater(len(packages), 1)

    def test_package_validation(self):
        key = decode_des_key(CONTROL_KEY)
        for package in ("", "!!!", base64.b64encode(b"short").decode(), base64.b64encode(b"123456789").decode()):
            with self.subTest(package=package):
                with self.assertRaises(DesError):
                    decrypt_text_cbc(package, key)
        with self.assertRaises(DesError):
            decode_base64_package("AQIDBAUGBwg=")  # 8-byte only -> no ciphertext block


class Lab4CliTests(unittest.TestCase):
    def run_cli(self, *args, input_text=None):
        return subprocess.run(
            [sys.executable, str(ROOT / "lab4.py"), *args],
            input=input_text,
            text=True,
            encoding="utf-8",
            capture_output=True,
            cwd=ROOT,
        )

    def test_block_encrypt_trace(self):
        result = self.run_cli(
            "block", "encrypt", "--block", CONTROL_PLAINTEXT, "--key", CONTROL_KEY, "--trace"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Після IP: CC00CCFFF0AAF0AA", result.stdout)
        self.assertIn("K1: 1B02EFFC7072", result.stdout)
        self.assertIn(f"Результат: {CONTROL_CIPHERTEXT}", result.stdout)

    def test_text_encrypt_decrypt_vectors(self):
        encrypted = self.run_cli(
            "text", "encrypt", "--key", CONTROL_KEY, "--text", "HELLO", "--test-iv", "0102030405060708"
        )
        self.assertEqual(encrypted.returncode, 0, encrypted.stderr)
        self.assertEqual(encrypted.stdout.strip(), "AQIDBAUGBwhZhXOTulwNWA==")
        decrypted = self.run_cli(
            "text", "decrypt", "--key", CONTROL_KEY, "--package", encrypted.stdout.strip()
        )
        self.assertEqual(decrypted.returncode, 0, decrypted.stderr)
        self.assertEqual(decrypted.stdout, "HELLO")

    def test_text_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "in.txt"
            pkg = tmp_path / "pkg.b64"
            out = tmp_path / "out.txt"
            src.write_text("Привіт 🙂\n", encoding="utf-8", newline="\n")
            enc = self.run_cli(
                "text", "encrypt", "--key", CONTROL_KEY, "--input", str(src), "--output", str(pkg)
            )
            self.assertEqual(enc.returncode, 0, enc.stderr)
            dec = self.run_cli(
                "text", "decrypt", "--key", CONTROL_KEY, "--package-file", str(pkg), "--output", str(out)
            )
            self.assertEqual(dec.returncode, 0, dec.stderr)
            self.assertEqual(out.read_text(encoding="utf-8"), "Привіт 🙂\n")

    def test_errors_have_nonzero_exit(self):
        result = self.run_cli("block", "encrypt", "--block", "ZZZZ", "--key", CONTROL_KEY)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Помилка", result.stderr)


if __name__ == "__main__":
    unittest.main()
