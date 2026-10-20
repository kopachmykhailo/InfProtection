
import unittest

from cipher_lab import (
    ALPHABET,
    prepare,
    substitution_encrypt,
    substitution_decrypt,
    vigenere_encrypt,
    vigenere_decrypt,
    block_encrypt,
    block_decrypt,
    column_encrypt,
    column_decrypt,
)


class CipherTests(unittest.TestCase):

    def test_alphabet_has_33_letters(self):
        self.assertEqual(len(ALPHABET), 33)
        self.assertEqual(len(set(ALPHABET)), 33)

    def test_substitution_round_trip(self):
        text = "Слава Україні! Ґанок, Єнот, Ідея, Їжак."
        encrypted = substitution_encrypt(text, "КРИПТО")
        self.assertEqual(
            substitution_decrypt(encrypted, "КРИПТО"),
            prepare(text)
        )

    def test_substitution_invalid_key(self):
        with self.assertRaises(ValueError):
            substitution_encrypt("ТЕСТ", "KEY")

    def test_vigenere_round_trip(self):
        text = "Слава Україні! Ґанок, Єнот, Ідея, Їжак."
        encrypted = vigenere_encrypt(text, "КЛЮЧ")
        self.assertEqual(
            vigenere_decrypt(encrypted, "КЛЮЧ"),
            prepare(text)
        )

    def test_vigenere_empty_key(self):
        with self.assertRaises(ValueError):
            vigenere_encrypt("ТЕСТ", "")

    def test_block_round_trip(self):
        text = "СЛАВАУКРАЇНІ"
        key = (3, 2, 5, 1, 4)
        encrypted = block_encrypt(text, key)
        self.assertEqual(block_decrypt(encrypted, key), text)

    def test_block_incomplete_block(self):
        self.assertEqual(
            block_encrypt("АБВГДЕЖ", (2, 1, 3)),
            "БАВДГЕЖ"
        )

    def test_block_invalid_key(self):
        with self.assertRaises(ValueError):
            block_encrypt("ТЕСТ", (1, 1, 3))

    def test_column_round_trip(self):
        text = "КРИПТОГРАФІЯ"
        key = (3, 1, 4, 2)
        encrypted, padding = column_encrypt(text, key)
        self.assertEqual(
            column_decrypt(encrypted, key, padding),
            text
        )

    def test_column_invalid_padding(self):
        with self.assertRaises(ValueError):
            column_decrypt("АБВГ", (1, 2), 2)

    def test_unicode_normalization(self):
        self.assertEqual(prepare("І\u0308"), prepare("Ї"))

    def test_empty_text(self):
        self.assertEqual(vigenere_encrypt("", "КЛЮЧ"), "")
        self.assertEqual(block_encrypt("", (1, 2, 3)), "")

    def test_vigenere_preserves_punctuation(self):
        self.assertEqual(vigenere_encrypt("А!А", "Б"), "Б!Б")

    def test_ten_messages_round_trip(self):
        messages = [
            "А",
            "Я",
            "Ґ",
            "Є І Ї",
            "Привіт, світе!",
            "Текст 123",
            "ПЕРЕВІРКА",
            "Рядок\nдругий",
            "Криптографія.",
            "СЛАВА УКРАЇНІ",
        ]

        for text in messages:
            prepared = prepare(text)

            self.assertEqual(
                substitution_decrypt(
                    substitution_encrypt(text, "КЛЮЧ"), "КЛЮЧ"
                ),
                prepared
            )

            self.assertEqual(
                vigenere_decrypt(
                    vigenere_encrypt(text, "КЛЮЧ"), "КЛЮЧ"
                ),
                prepared
            )

            key = (2, 1, 3)
            self.assertEqual(
                block_decrypt(block_encrypt(text, key), key),
                prepared
            )

            column_key = (3, 1, 2)
            encrypted, padding = column_encrypt(text, column_key)
            self.assertEqual(
                column_decrypt(encrypted, column_key, padding),
                prepared
            )


if __name__ == "__main__":
    unittest.main()
