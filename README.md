
# Лабораторна робота №2
## Квадрат Полібія та шифр Гронсфельда

### Мета
Навчитися:
- формувати ключовий квадрат 6x6,
- кодувати символи координатами Полібія,
- виконувати циклічний зсув за рядками,
- застосовувати цифровий ключ Гронсфельда,
- перевіряти обернені операції тестами.

### Інструменти
- Python 3.10+
- UTF-8
- unittest
- Unicode NFC

### Підтримувані режими
1. Координатний режим Полібія.
2. Циклічний зсув за рядками квадрата.
3. Шифр Гронсфельда.

### Вибір мови
- `uk` — український алфавіт + цифри 0..2
- `lat` — латинський алфавіт + цифри 0..9

### Команди запуску
**Побудова квадрата Полібія**
```bash
python cipher_lab.py square --lang uk --key "БЕЗПЕКА"
```

**Координатний метод Полібія**
```bash
python cipher_lab.py encrypt --algorithm coordinates --lang uk --key "БЕЗПЕКА" --text "СЛАВА"
python cipher_lab.py decrypt --algorithm coordinates --lang uk --key "БЕЗПЕКА" --text "44 35 16 21 16"
python cipher_lab.py encrypt --algorithm coordinates --lang lat --key "SECURITY" --text "HELLO"
```

**Циклічний зсув за рядками**
```bash
python cipher_lab.py encrypt --algorithm row_shift --lang uk --key "БЕЗПЕКА" --text "СЛАВА"
python cipher_lab.py decrypt --algorithm row_shift --lang uk --key "БЕЗПЕКА" --text "ЧТЖИЖ"
```

**Шифр Гронсфельда**
```bash
python cipher_lab.py encrypt --algorithm gronsfeld --lang uk --key "31415" --text "СЛАВА"
python cipher_lab.py decrypt --algorithm gronsfeld --lang uk --key "31415" --text "ФМҐГД"
python cipher_lab.py encrypt --algorithm gronsfeld --lang lat --key "2718" --text "HELLO WORLD"
```

### Робота з файлами
```bash
python cipher_lab.py encrypt --algorithm gronsfeld --lang uk --key "31415" --input input.txt --output output.txt
```

### Запуск тестів
```bash
python -m unittest discover -s tests -v
```

### Важливі правила
- Вхідні та вихідні рядки нормалізуються через Unicode NFC.
- Літери переводяться у верхній регістр.
- У координатному режимі токени мають вигляд `rowcol`, розділені пробілами.
- У шифрі Гронсфельда ключ зберігається як рядок цифр; сторонні символи не споживають цифру ключа.
- Порожній ключ, нецифровий ключ або ключ, що складається лише з нулів, є некоректним.

### Контрольні вектори
- Український Polybius coordinates: `СЛАВА -> 44 35 16 21 16`
- Латинський Polybius coordinates: `HELLO -> 32 12 35 35 42`
- Український row shift: `СЛАВА -> ЧТЖИЖ`
- Латинський row shift: `HELLO -> OYVVZ`
- Український Gronsfeld: `СЛАВА -> ФМҐГД`
- Латинський Gronsfeld: `HELLO WORLD -> JLMTQ DPZNK`
