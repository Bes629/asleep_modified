# Asleep Scanner — Dahua Brute Scanner (Modified v1.0 Beta)

Брутфорс-сканер камер Dahua с поддержкой эксплойтов, массового сканирования и автоматических снапшотов.

> **Автор оригинального кода не несёт ответственности за любые незаконные действия.**
> Только в образовательных целях.

![Terminal record](tty.gif)

---

## Возможности

- **Брутфорс** — перебор комбинаций логин/пароль через DHIP-протокол (бинарный)
- **Эксплойты** — CVE-2021-33044 (NetKeyboard Direct), CVE-2021-33045 (Loopback)
- **Определение микрофона** — классификация камер по наличию звука/микрофона
- **Masscan** — быстрое сканирование IP-диапазонов с последующим брутфорсом
- **Геолокация** — сканирование по странам (название или ISO-код: `Russia`, `RU`)
- **Снапшоты** — автоматический скриншот с фильтрацией мусора (opencv)
- **Экспорт** — CSV (все / с микрофоном / без микрофона), XML для SmartPSS
- **Кросс-платформенность** — Linux, Windows, macOS

---

## Структура

```
asleep_scanner-master/
├── asleep.py              # Точка входа
├── nonstop.py             # Бесконечный режим
├── asleep/                # Ядро сканера
│   ├── config.py          # Конфигурация
│   ├── core.py            # Masscan + оркестрация
│   ├── brute.py           # Брутфорс + PoC
│   ├── dahua.py           # DHIP-протокол
│   ├── export.py          # CSV / XML
│   ├── geolocation.py     # Страны / IP-блоки
│   └── snapshot.py        # Снапшоты (opencv)
├── pocs/                  # Эксплойты
│   ├── base.py            # Общие утилиты (DHIP, хеши, порты)
│   ├── cve_2021_33044.py  # NetKeyboard Direct bypass
│   └── cve_2021_33045.py  # Loopback bypass
├── utils/                 # Утилиты
│   ├── args.py            # Аргументы CLI
│   ├── color.py           # Цветной вывод
│   ├── credentials.py     # Загрузка комбинаций
│   ├── logo.py            # ASCII-арт
│   └── masscan.py         # Парсер вывода masscan
└── data/                  # Данные
    ├── combinations.txt   # login:password
    ├── logins.txt         # Только логины
    └── passwords.txt      # Только пароли
```

---

## Установка

### Требования

- **Python 3.8+** ( Linux / Windows / macOS)
- [**masscan**](https://github.com/robertdavidgraham/masscan) — для сканирования портов
- **Windows**: [**WinPcap**](https://www.winpcap.org/) или [**Npcap**](https://npcap.com/)

### Установка зависимостей
Windows
```bash
git clone https://github.com/Bes629/asleep_scanner.git
cd asleep_scanner
pip install -r requirements.txt
```
### Проверка

```bash
python asleep.py --help
```

### Установка зависимостей
Linux/macOS
```bash
git clone https://github.com/Bes629/asleep_scanner.git
cd asleep_scanner
pip3 install -r requirements.txt
```

### Проверка

```bash
python3 asleep.py --help
```

---

## Использование

### Базовые команды

```bash
# Сканирование файла + брутфорс
python3 asleep.py -m -s ips.txt

# Сканирование по стране
python3 asleep.py --country

# Сканирование по случайной стране
python3 asleep.py --random-country

# Только брутфорс (без masscan)
python3 asleep.py -b ips.txt
```

### IP-диапазоны (флаг `-i`)

Прямой ввод IP-целей без файла:

```bash
# CIDR
python3 asleep.py -i 192.168.1.0/24

# Диапазон
python3 asleep.py -i 10.0.0.1-10.0.0.255

# Микс
python3 asleep.py -i 192.168.1.0/24,10.0.0.1-10.0.0.5,172.16.0.0/16
```

Автоматически запускает masscan → брутфорс результатов.

### Порты (флаг `-p`)

Поддерживает диапазоны, списки и микс:

```bash
# Диапазон
python3 asleep.py -m -s ips.txt -p 80-90

# Список
python3 asleep.py -m -s ips.txt -p 37777,37778,47777

# Микс
python3 asleep.py -m -s ips.txt -p 80,8080,37777
```

Порты по умолчанию определены в `pocs/base.py` → `DEFAULT_PORTS`.

### Страны

Поддерживает полные названия и ISO-коды:

```bash
python3 asleep.py --country
# Ввод: RU / ru / Russia / russia → Russia

python3 asleep.py --country
# Ввод: US → United States
# Ввод: DE → Germany
# Ввод: KZ → Kazakhstan
```

### Другие флаги

| Флаг | Описание |
|------|----------|
| `-m, --masscan` | Запустить masscan + брутфорс |
| `-t THREADS` | Потоки masscan (по умолчанию: 3000) |
| `-l` | Использовать `logins.txt` + `passwords.txt` вместо `combinations.txt` |
| `--masscan-resume` | Продолжить прерванный masscan |
| `--no-snapshots` | Без снапшотов |
| `--no-xml` | Без XML-файлов SmartPSS |
| `--dead` | Записать мёртвые камеры в `dead_cams.txt` |
| `-d, --debug` | Отладочный вывод |

---

## Эксплойты

### CVE-2021-33044

Обход аутентификации через `loginType=Direct` с `clientType=NetKeyboard`. Извлекает учётные данные из внутренней таблицы пользователей.

### CVE-2021-33045

Обход аутентификации через `loginType=Loopback` с `clientType=Dahua3.0-Web3.0-NOTUSED`. Аналогичен CVE-2021-33044, но использует другой вектор. Полезен для NVR/DVR — извлекаетcredentials подключённых камер.

### Порядок проверки

Для каждого хоста:
1. **PoC** → CVE-2021-33044 → CVE-2021-33045
2. Если PoC нашёл credentials → верификация через DHIP → снапшот
3. Если PoC не сработал → **брутфорс** по комбинациям

---

## Определение микрофона

Сканер определяет наличие микрофона/звука на камере и сохраняет результат в CSV:

| Колонка | Описание |
|---------|----------|
| `ip` | IP-адрес |
| `port` | Порт |
| `login` | Логин |
| `password` | Пароль |
| `channels` | Количество каналов |
| `model` | Модель (с суффиксом `-Sound-Mic` если есть микрофон) |
| `mic` | `YES` / `NO` |

Автоматически создаётся 3 файла:
- `results_*.csv` — все камеры
- `mic_results_*.csv` — только с микрофоном
- `no_mic_results_*.csv` — без микрофона

---

## Просмотр камер

| Платформа | Программа |
|-----------|-----------|
| Windows / macOS | [SmartPSS](https://dahuawiki.com/SmartPSS) |
| Linux | [TaniDVR](http://tanidvr.sourceforge.net/) |

---

## Конфигурация

Основные настройки в `asleep/config.py`:

| Параметр | Значение | Описание |
|----------|----------|----------|
| `global_ports` | `DEFAULT_PORTS` | Порты для masscan |
| `default_masscan_threads` | `3000` | Потоки masscan |
| `default_brute_threads` | `160` | Потоки брутфорса |
| `default_snap_threads` | `140` | Потоки снапшотов |

Порты по умолчанию: `DEFAULT_PORTS` из `pocs/base.py`.

---

## Примеры

```bash
# Полное сканирование по случайной стране
python3 asleep.py --random-country
# Сканирование подсети
python3 asleep.py -i 192.168.0.0/16 -p 37777,37778
# Брутфорс файла с кастомными портами
python3 asleep.py -b cameras.txt -p 80,8080
# Страна + кастомные потоки
python3 asleep.py --country -t 5000
# Бесконечный режим
python3 nonstop.py
```
