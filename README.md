# Лабораторна робота 4 — алгоритм шифрування DES

Навчальна реалізація DES: шифрування/розшифрування одного 64-бітового блока та
режим **DES CBC** для UTF-8 тексту (PKCS#7, випадковий IV, пакет `Base64(IV||шифротекст)`).

- Python 3.10+
- Зовнішні залежності не потрібні
- Ключ для прикладів: `133457799BBCDFF1`

## Команди

### 1. Тести (покриття перевірками)

```powershell
python -m unittest discover -s tests -v
python -m unittest tests.test_lab4 -v
```

### 2. DES — блок (64 біти): encrypt і decrypt

```powershell
# Encrypt (шифрування)
python lab4.py block encrypt --block 0123456789ABCDEF --key 133457799BBCDFF1
# Очікувано: 85E813540F0AB405

# Decrypt (розшифрування)
python lab4.py block decrypt --block 85E813540F0AB405 --key 133457799BBCDFF1
# Очікувано: 0123456789ABCDEF
```

### 3. DES CBC — текст: encrypt і decrypt

```powershell
# Encrypt (шифрування, відтворюваний тестовий IV)
python lab4.py text encrypt --key 133457799BBCDFF1 --text "HELLO" --test-iv 0102030405060708
# Очікувано: AQIDBAUGBwhZhXOTulwNWA==

# Decrypt (розшифрування)
python lab4.py text decrypt --key 133457799BBCDFF1 --package "AQIDBAUGBwhZhXOTulwNWA=="
# Очікувано: HELLO
```

> Примітка: `--test-iv` використовується лише для відтворюваної перевірки; у звичайному режимі `text encrypt` без `--test-iv` генерує випадковий IV.
