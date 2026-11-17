import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lab3 import _atomic_write_utf8
from lab3_cipher import (
    LATIN_ALPHABET,
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
    vernam_encrypt_with_key,
    xor_bytes,
)


ROOT = Path(__file__).resolve().parents[1]


class Lab3BigramCipherTests(unittest.TestCase):
    def test_key_square_vector_and_completeness(self):
        square = build_latin_square("MONARCHY")
        self.assertEqual(
            square,
            [
                list("MONAR"),
                list("CHYBD"),
                list("EFGIK"),
                list("LPQST"),
                list("UVWXZ"),
            ],
        )
        flattened = "".join(symbol for row in square for symbol in row)
        self.assertEqual(len(flattened), 25)
        self.assertEqual(set(flattened), set(LATIN_ALPHABET))
        self.assertEqual(
            format_latin_square(square),
            "   1 2 3 4 5\n"
            "1  M O N A R\n"
            "2  C H Y B D\n"
            "3  E F G I K\n"
            "4  L P Q S T\n"
            "5  U V W X Z",
        )

    def test_key_is_normalized_and_repeats_are_removed(self):
        self.assertEqual(build_latin_square("monarchyj"), build_latin_square("MONARCHYI"))

    def test_invalid_key_is_rejected(self):
        for key in ("", "KEY WORD", "CLÉ", "123"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    build_latin_square(key)

    def test_prepare_control_examples(self):
        vectors = {
            "INSTRUMENTS": "INSTRUMENTSX",
            "BALLOON": "BALXLOON",
            "ODD": "ODDX",
            "XX": "XQXQ",
            "JIG": "IXIG",
        }
        for source, expected in vectors.items():
            with self.subTest(source=source):
                self.assertEqual(prepare_bigrams(source), expected)
                self.assertEqual(len(expected) % 2, 0)
        self.assertEqual(format_bigrams("INST RUM ENTSX".replace(" ", "")), "IN ST RU ME NT SX")

    def test_prepare_filters_or_rejects_non_latin_characters(self):
        self.assertEqual(prepare_bigrams("Hello, world!"), "HELXLOWORLDX")
        with self.assertRaises(ValueError):
            prepare_bigrams("Hello, world!", strict=True)
        for text in ("", "123", "!!!"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    prepare_bigrams(text)

    def test_playfair_control_vector(self):
        ciphertext = playfair_encrypt("INSTRUMENTS", "MONARCHY")
        self.assertEqual(ciphertext, "GATLMZCLRQXA")
        self.assertEqual(playfair_decrypt(ciphertext, "MONARCHY"), "INSTRUMENTSX")

    def test_playfair_encrypts_same_row_column_and_rectangle(self):
        square = build_latin_square("MONARCHY")
        self.assertEqual(playfair_encrypt("MO", "MONARCHY"), "ON")
        self.assertEqual(playfair_encrypt("MC", "MONARCHY"), "CE")
        self.assertEqual(playfair_encrypt("MH", "MONARCHY"), "OC")
        self.assertEqual(len(square), 5)

    def test_playfair_wraps_square_edges(self):
        self.assertEqual(playfair_encrypt("RM", "MONARCHY"), "MO")
        self.assertEqual(playfair_decrypt("MO", "MONARCHY"), "RM")
        self.assertEqual(playfair_encrypt("UM", "MONARCHY"), "MC")
        self.assertEqual(playfair_decrypt("MC", "MONARCHY"), "UM")

    def test_playfair_accepts_grouped_ciphertext(self):
        self.assertEqual(
            playfair_decrypt("GA TL MZ CL RQ XA", "MONARCHY"),
            "INSTRUMENTSX",
        )

    def test_playfair_rejects_invalid_ciphertext(self):
        for ciphertext in ("", "ABC", "AB!", "AJ"):
            with self.subTest(ciphertext=ciphertext):
                with self.assertRaises(ValueError):
                    playfair_decrypt(ciphertext, "MONARCHY")

    def test_playfair_round_trip_for_multiple_inputs(self):
        messages = (
            "A",
            "JIG",
            "BALLOON",
            "XX",
            "One more sample",
            "Cryptography!",
            "A long sentence with repeated letters.",
            "Playfair",
            "INSTRUMENTS",
            "ZEBRA",
        )
        for message in messages:
            with self.subTest(message=message):
                encrypted = playfair_encrypt(message, "MONARCHY")
                self.assertEqual(
                    playfair_decrypt(encrypted, "MONARCHY"),
                    prepare_bigrams(message),
                )

    def test_double_square_control_vector(self):
        ciphertext = double_square_encrypt("SECURITY", "EXAMPLE", "KEYWORD")
        self.assertEqual(ciphertext, "NMDWQIPP")
        self.assertEqual(
            double_square_decrypt(ciphertext, "EXAMPLE", "KEYWORD"),
            "SECURITY",
        )

    def test_double_square_prepares_repeats_and_round_trips(self):
        ciphertext = double_square_encrypt("BALLOON", "EXAMPLE", "KEYWORD")
        self.assertEqual(
            double_square_decrypt(ciphertext, "EXAMPLE", "KEYWORD"),
            "BALXLOON",
        )

    def test_double_square_rejects_invalid_ciphertext(self):
        with self.assertRaises(ValueError):
            double_square_decrypt("ABC", "EXAMPLE", "KEYWORD")


class Lab3VernamTests(unittest.TestCase):
    def test_vernam_hex_and_base64_vectors(self):
        ciphertext, key = vernam_encrypt_with_key(b"HELLO".decode("ascii"), bytes.fromhex("1A2B3C4D5E"))
        self.assertEqual(key, "Gis8TV4=")
        self.assertEqual(ciphertext, "Um5wARE=")
        self.assertEqual(vernam_decrypt(ciphertext, key), "HELLO")

    def test_vernam_utf8_vector_uses_byte_length(self):
        ciphertext, key = vernam_encrypt_with_key("Я", bytes.fromhex("0102"))
        self.assertEqual(key, "AQI=")
        self.assertEqual(ciphertext, "0a0=")
        self.assertEqual(len("Я"), 1)
        self.assertEqual(len("Я".encode("utf-8")), 2)
        self.assertEqual(vernam_decrypt(ciphertext, key), "Я")

    def test_vernam_random_round_trip_preserves_exact_unicode(self):
        messages = ("Hello", "Слава Україні", "🙂", "", "line 1\nline 2", "e\u0301")
        for message in messages:
            with self.subTest(message=message):
                ciphertext, key = vernam_encrypt(message)
                self.assertEqual(vernam_decrypt(ciphertext, key), message)
                self.assertEqual(len(base64.b64decode(key)), len(message.encode("utf-8")))
                self.assertEqual(len(base64.b64decode(ciphertext)), len(message.encode("utf-8")))

    def test_generated_keys_are_distinct_and_system_random(self):
        first = vernam_encrypt("repeated public test input")[1]
        second = vernam_encrypt("repeated public test input")[1]
        self.assertNotEqual(first, second)

    def test_xor_is_involutive_and_checks_equal_lengths(self):
        plaintext = bytes(range(32))
        key = bytes(reversed(range(32)))
        ciphertext = xor_bytes(plaintext, key)
        self.assertEqual(xor_bytes(ciphertext, key), plaintext)
        with self.assertRaises(ValueError):
            xor_bytes(b"short", b"longer")
        with self.assertRaises(TypeError):
            xor_bytes("text", b"key!")

    def test_reusing_a_key_reveals_xor_of_public_plaintexts(self):
        first_plaintext = b"ATTACK AT DAWN"
        second_plaintext = b"DEFEND AT DUSK"
        reused_key = bytes.fromhex("00112233445566778899aabbccdd")
        first_ciphertext = xor_bytes(first_plaintext, reused_key)
        second_ciphertext = xor_bytes(second_plaintext, reused_key)
        self.assertEqual(
            xor_bytes(first_ciphertext, second_ciphertext),
            xor_bytes(first_plaintext, second_plaintext),
        )

    def test_vernam_rejects_invalid_base64_and_length_mismatch(self):
        for ciphertext, key in (("AA==!", "AA=="), ("AA==", "AAA="), ("AA==", "AA")):
            with self.subTest(ciphertext=ciphertext, key=key):
                with self.assertRaises(ValueError):
                    vernam_decrypt(ciphertext, key)

    def test_vernam_rejects_non_utf8_plaintext(self):
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            vernam_decrypt("gA==", "AA==")


class Lab3CliTests(unittest.TestCase):
    def _run_cli(self, *arguments, input_text=None):
        return subprocess.run(
            [sys.executable, str(ROOT / "lab3.py"), *arguments],
            input=input_text,
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )

    def test_playfair_cli_encrypt_decrypt(self):
        encrypted = self._run_cli(
            "encrypt", "--algorithm", "playfair", "--key", "MONARCHY", "--text", "INSTRUMENTS"
        )
        self.assertEqual(encrypted.returncode, 0, encrypted.stderr)
        self.assertEqual(encrypted.stdout.strip(), "GATLMZCLRQXA")
        decrypted = self._run_cli(
            "decrypt", "--algorithm", "playfair", "--key", "MONARCHY", "--text", encrypted.stdout.strip()
        )
        self.assertEqual(decrypted.returncode, 0, decrypted.stderr)
        self.assertEqual(decrypted.stdout.strip(), "INSTRUMENTSX")

    def test_vernam_cli_generates_key_and_round_trips_from_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.txt"
            encrypted = root / "ciphertext.txt"
            key_file = root / "key.txt"
            recovered = root / "recovered.txt"
            source.write_bytes("Привіт 🙂\r\n".encode("utf-8"))
            encrypt_result = self._run_cli(
                "encrypt",
                "--algorithm",
                "vernam",
                "--input",
                str(source),
                "--output",
                str(encrypted),
                "--key-output",
                str(key_file),
            )
            self.assertEqual(encrypt_result.returncode, 0, encrypt_result.stderr)
            decrypt_result = self._run_cli(
                "decrypt",
                "--algorithm",
                "vernam",
                "--input",
                str(encrypted),
                "--key-file",
                str(key_file),
                "--output",
                str(recovered),
            )
            self.assertEqual(decrypt_result.returncode, 0, decrypt_result.stderr)
            self.assertEqual(recovered.read_bytes(), source.read_bytes())

    def test_vernam_cli_rejects_colliding_output_paths_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "same.txt"
            destination.write_text("existing", encoding="utf-8")
            result = self._run_cli(
                "encrypt",
                "--algorithm",
                "vernam",
                "--text",
                "demo",
                "--output",
                str(destination),
                "--key-output",
                str(destination),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(destination.read_text(encoding="utf-8"), "existing")

    def test_atomic_file_write_keeps_utf8_and_newlines(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "output.txt"
            _atomic_write_utf8(destination, "Я\r\n🙂")
            self.assertEqual(destination.read_bytes(), "Я\r\n🙂".encode("utf-8"))
            result = self._run_cli(
                "square", "--key", "MONARCHY", "--output", str(destination)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("M O N A R", destination.read_text(encoding="utf-8"))
            self.assertFalse(any(path.suffix == ".tmp" for path in destination.parent.iterdir()))

    def test_cli_errors_have_nonzero_exit_code(self):
        result = self._run_cli("decrypt", "--algorithm", "vernam", "--text", "AA==")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Помилка:", result.stderr)


if __name__ == "__main__":
    unittest.main()
