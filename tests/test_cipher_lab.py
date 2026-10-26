
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
    build_square,
    format_square,
    polybius_coordinates_encrypt,
    polybius_coordinates_decrypt,
    polybius_row_shift_encrypt,
    polybius_row_shift_decrypt,
    gronsfeld_encrypt,
    gronsfeld_decrypt,
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

    def test_polybius_coordinates_vectors(self):
        self.assertEqual(
            polybius_coordinates_encrypt("СЛАВА", "БЕЗПЕКА", "uk"),
            "44 35 16 21 16"
        )
        self.assertEqual(
            polybius_coordinates_decrypt("44 35 16 21 16", "БЕЗПЕКА", "uk"),
            "СЛАВА"
        )
        self.assertEqual(
            polybius_coordinates_encrypt("HELLO", "SECURITY", "lat"),
            "32 12 35 35 42"
        )
        self.assertEqual(
            polybius_coordinates_decrypt("32 12 35 35 42", "SECURITY", "lat"),
            "HELLO"
        )

    def test_polybius_row_shift_vectors(self):
        self.assertEqual(
            polybius_row_shift_encrypt("СЛАВА", "БЕЗПЕКА", "uk"),
            "ЧТЖИЖ"
        )
        self.assertEqual(
            polybius_row_shift_decrypt("ЧТЖИЖ", "БЕЗПЕКА", "uk"),
            "СЛАВА"
        )
        self.assertEqual(
            polybius_row_shift_encrypt("HELLO", "SECURITY", "lat"),
            "OYVVZ"
        )
        self.assertEqual(
            polybius_row_shift_decrypt("OYVVZ", "SECURITY", "lat"),
            "HELLO"
        )

    def test_gronsfeld_vectors(self):
        self.assertEqual(
            gronsfeld_encrypt("СЛАВА", "31415", "uk"),
            "ФМҐГД"
        )
        self.assertEqual(
            gronsfeld_decrypt("ФМҐГД", "31415", "uk"),
            "СЛАВА"
        )
        self.assertEqual(
            gronsfeld_encrypt("УКРАЇНІ", "31415", "uk"),
            "ЦЛФБНРЇ"
        )
        self.assertEqual(
            gronsfeld_decrypt("ЦЛФБНРЇ", "31415", "uk"),
            "УКРАЇНІ"
        )
        self.assertEqual(
            gronsfeld_encrypt("HELLO WORLD", "2718", "lat"),
            "JLMTQ DPZNK"
        )
        self.assertEqual(
            gronsfeld_decrypt("JLMTQ DPZNK", "2718", "lat"),
            "HELLO WORLD"
        )

    def test_square_generation(self):
        square = build_square("БЕЗПЕКА", "uk")
        self.assertEqual(len(square), 6)
        self.assertEqual(len(square[0]), 6)
        self.assertEqual(len({symbol for row in square for symbol in row}), 36)
        self.assertEqual(
            format_square(square),
            "   1 2 3 4 5 6\n"
            "1  Б Е З П К А\n"
            "2  В Г Ґ Д Є Ж\n"
            "3  И І Ї Й Л М\n"
            "4  Н О Р С Т У\n"
            "5  Ф Х Ц Ч Ш Щ\n"
            "6  Ь Ю Я 0 1 2"
        )


if __name__ == "__main__":
    unittest.main()
