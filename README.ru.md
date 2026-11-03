# PHP Form Spam Checker — документация на русском

[![PHP](https://img.shields.io/badge/PHP-8.5.12-8892bf.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Многослойный антиспам-чекер для любых PHP-форм.** Встраивается в обычный
`mail()`-обработчик, самописную CMS, легаси-портал или в приложение на
Node/Go/Python через CLI/HTTP-мост. Без капчи, без внешних API и без
зависимостей Composer в runtime.

Каждый вердикт несёт доказательства: какие проверки сработали, с какими
баллами и почему.

> English documentation: [README.md](README.md)

## Возможности

| Слой | Проверка | Что ловит |
|---|---|---|
| Приманка | `honeypot` | Ботов, заполняющих скрытые поля |
| Поведение | `time_trap` | Отправку через миллисекунды после отрисовки страницы (HMAC-токен, привязан к форме) |
| Идентификация | `user_agent` | HTTP-библиотеки, headless-браузеры, сканеры, пустой UA |
| Объём | `rate_limit` | Счётчики на IP, переживающие рестарт PHP-FPM (файлы + flock) |
| Полезная нагрузка | `length` | Огромные поля и управляющие символы |
| Инъекции | `sql_injection` | `UNION SELECT`, `DROP TABLE`, тавтологии, time-based пробы |
| Инъекции | `xss` | Теги script, обработчики событий, `javascript:`, закодированные полезные нагрузки |
| Контент | `links` | Флуд ссылками, сокращатели, обфусцированные `hxxp://` |
| Контент | `keywords` | Настраиваемый многоязычный словарь спама и регулярные выражения |
| Контакты | `email` | Битые адреса и одноразовые почтовые домены |
| Контент | `repetition` | «ааааааа», повторяющиеся слова |
| Контент | `language` | Смешанные алфавиты (гомоглифы), по умолчанию выключено |

Дополнительно:

- **Подписанный токен времени** — `FormProtector::fields()` выводит honeypot и HMAC-токен; подделать или переиспользовать токен в другой форме нельзя.
- **Надёжное хранилище** — файловые счётчики работают на shared-хостинге без Redis/APCu; интерфейс позволяет подключить своё хранилище.
- **Вердикты с доказательствами** — `Verdict::reasons()`, баллы по каждой проверке, сериализация в JSON.
- **Приватное журналирование** — JSONL-журнал вердиктов хеширует IP и скрывает поля, пока PII-режим не включён явно.
- **Мосты для не-PHP** — CLI `bin/spam-check` и HTTP-эндпоинт `public/check.php`.
- **Одна копия на сервер** — `/var/www/lib/PHP-Form-Spam-Checker`, конфиг на каждый сайт, режимы `off`/`shadow`/`enforce`.

## Требования

- PHP **8.5.12** (проверено; совместимо с веткой 8.5)
- `ext-mbstring`, `ext-json`
- Зависимостей Composer в runtime нет

## Установка

Через Composer:

```bash
composer require paulmann/php-form-spam-checker
```

Или простым копированием: положить каталог на сервер и подключить `autoload.php`.

## Быстрый старт: обычная PHP-форма

```php
<?php
declare(strict_types=1);

use FormSpamChecker\Config;
use FormSpamChecker\FormProtector;
use FormSpamChecker\SpamChecker;

require __DIR__ . '/vendor/autoload.php';

$config = Config::fromFile(__DIR__ . '/config/spam-checker.php');
$checker = new SpamChecker($config);
$protector = new FormProtector($checker, $config);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $verdict = $protector->verifyRequest('contact');

    if ($verdict->isSpam()) {
        http_response_code(400);
        exit('Заявка отклонена антиспам-проверкой.');
    }

    // ... отправка письма
}
?>
<form method="post">
    <?= $protector->fields('contact') /* honeypot + подписанный токен */ ?>
    <input name="email" type="email" required>
    <textarea name="message" required></textarea>
    <button type="submit">Отправить</button>
</form>
```

Если страница кэшируется и токен времени не подходит — выключите `time_trap`
в конфиге, остальной конвейер продолжит работать.

## Режимы встраивания

### 1. Внутри PHP

Напрямую `SpamChecker` (см. выше) или общий guard из модуля:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

Guard управляется конфигом `config/sites/<host>.php` и поддерживает режимы
`off` / `shadow` / `enforce`. Подробности: [docs/INTEGRATION.ru.md](docs/INTEGRATION.ru.md).

### 2. Из Node / Go / Python (CLI-мост)

```bash
php bin/spam-check --config=/etc/spam.php --form=register --base64=BASE64_JSON
```

В STDOUT — один JSON-объект, пригодный для `JSON.parse`. Коды выхода: `0` —
чисто, `1` — подозрительно, `2` — спам, `3` — ошибка. Пример:
[examples/node/bridge.mjs](examples/node/bridge.mjs).

### 3. По HTTP (эндпоинт)

Разверните `public/check.php` и отправляйте POST
`{"form":..., "fields":{...}, "context":{"ip":...,"userAgent":...}}`.
Защитите эндпоинт ключом `endpoint.key` и заголовком `X-Spam-Checker-Key`.

## Развёртывание на сервере: одна копия на все сайты

```text
/var/www/lib/PHP-Form-Spam-Checker/
├── src/            # библиотека
├── bin/spam-check  # CLI-мост
├── integrations/   # guard.php, auto-prepend.php
├── config/sites/   # конфиг на каждый хост
├── var/sites/      # счётчики по хостам
└── var/log/        # журналы вердиктов по хостам
```

В обработчик формы добавляется одна строка:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

и создаётся `config/sites/<host>.php`:

```php
<?php
return [
    'site' => 'example.ru',
    'mode' => 'shadow',            // off | shadow | enforce
    'form' => 'contact',
    'match' => ['#^/feedback\.php#'],
    'skip'  => ['#^/admin#', '#^/auth#'],
    'config' => [
        'rate_limit' => ['max' => 8, 'window' => 900],
        'links' => ['max' => 2],
    ],
];
```

Начинайте с `shadow` (только журнал), просмотрите `var/log/sites/<host>.jsonl`,
затем переключите на `enforce`. Скрипт `deploy/install-shared.sh` раскладывает
модуль с правильными владельцами и правами.

## Конфигурация

PHP-массив (возвращается из файла) или JSON. Все ключи необязательны,
значения по умолчанию безопасны. Основные:

| Ключ | По умолчанию | Смысл |
|---|---|---|
| `thresholds.spam` | `60` | балл, при котором заявка считается спамом |
| `thresholds.suspicious` | `30` | балл, при котором она становится подозрительной |
| `time_trap.secret` | — | HMAC-секрет (обязателен, если включён time trap) |
| `rate_limit.max` / `window` | `8` / `900` | запросов с одного IP за окно |
| `keywords.words` | стартовый список RU+EN | словарь спама |
| `links.max` | `2` | сколько ссылок допустимо в сообщении |
| `email.disposable_domains` | ~70 доменов | дополнительные одноразовые домены |
| `storage.path` | временный каталог | хранилище счётчиков |
| `log.path` | — | JSONL-журнал вердиктов |
| `log.pii` | `false` | хранить сырой IP и примеры полей |
| `forms.<id>` | — | переопределения для конкретной формы |

Полный справочник: [docs/CONFIG.md](docs/CONFIG.md). Семантика проверок:
[docs/CHECKS.md](docs/CHECKS.md).

## Тесты

```bash
composer install
composer test              # PHPUnit: 180 тестов, 465 утверждений
composer lint              # php -l по src, tests, bin
```

CI прогоняет набор на PHP 8.5.12 и 8.5 со строгими проверками предупреждений,
рискованных тестов и устареваний.

## Безопасность

- Никаких сетевых вызовов, `eval` и shell.
- Токен времени — HMAC-SHA-256, сравнение за постоянное время, привязка к id формы.
- HTTP-эндпоинт принимает только POST, ограничивает тело запроса и умеет требовать общий ключ.
- Журналирование по умолчанию не сохраняет персональные данные.
- Об уязвимостях — по [SECURITY.md](SECURITY.md).

## Лицензия

[MIT](LICENSE) © 2026 Paulmann
