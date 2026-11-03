# Встраивание: практическое руководство

Три способа использования, от простого к «серверному». Все они делят один
`FormSpamChecker\Config` и одну модель вердикта.

## 1. Внутри PHP-формы

```php
<?php
declare(strict_types=1);

use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\FormProtector;
use FormSpamChecker\SpamChecker;

require __DIR__ . '/vendor/autoload.php';

$config = Config::fromArray([
    'storage' => ['path' => __DIR__ . '/var/spam'],
    'log' => ['enabled' => true, 'path' => __DIR__ . '/var/spam/verdicts.jsonl'],
    'time_trap' => ['enabled' => true, 'secret' => getenv('SPAM_SECRET') ?: ''],
]);

$checker = new SpamChecker($config);
$protector = new FormProtector($checker, $config);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $verdict = $protector->verify($_POST, 'contact', Context::fromGlobals());

    if ($verdict->isSpam()) {
        http_response_code(400);
        exit('Заявка отклонена антиспам-проверкой.');
    }

    // ... отправка письма / запись в БД
}
?>
<form method="post">
    <?= $protector->fields('contact') ?>
    <input name="email" type="email" required>
    <textarea name="message" required></textarea>
    <button type="submit">Отправить</button>
</form>
```

Проверку вызывайте **до** отправки письма и записи в БД; вердикт
`suspicious` не блокируется автоматически — решите сами, нужна ли модерация
(`$verdict->reasons()`).

## 2. Общий модуль на сервере (одна копия)

Раскладка:

```text
/var/www/lib/PHP-Form-Spam-Checker/
├── autoload.php
├── src/
├── bin/spam-check
├── integrations/guard.php
├── config/sites/<host>.php
├── var/sites/<host>/        # счётчики
└── var/log/sites/<host>.jsonl
```

Установка/обновление (root): `deploy/install-shared.sh /path/to/checkout`.

В обработчик формы, **до** чтения входных данных, добавляется одна строка:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

Конфиг сайта — `config/sites/<host>.php`:

```php
<?php
return [
    'site' => 'example.ru',
    'mode' => 'shadow',                 // off | shadow | enforce
    'form' => 'contact',
    'response' => 'auto',               // auto | json | html | silent
    'match' => ['#^/feedback\.php#'],   // какие URI проверять (пусто = любой POST)
    'skip'  => ['#^/admin#', '#^/login#', '#^/api/internal#'],
    'config' => [
        'rate_limit' => ['max' => 8, 'window' => 900],
        'links' => ['max' => 2],
        'log' => ['enabled' => true],
    ],
];
```

Порядок внедрения:

1. `mode = shadow` на 1–3 дня: всё пишется в журнал, сайт ведёт себя как раньше.
2. Смотрим `var/log/sites/<host>.jsonl`, правим конфиг по ложным срабатываниям.
3. Переключаем `mode = enforce`: спам получает HTTP 400, приложение его не видит.
   `response = silent` возвращает HTTP 200 с пустым телом.

### Интеграция в контроллер

Если ответ формирует фреймворк, `guard.php` не подключают (он завершает
скрипт), а оценивают запрос:

```php
require_once '/var/www/lib/PHP-Form-Spam-Checker/autoload.php';

$verdict = FormSpamChecker\Integration\FormGuard::evaluateFor(
    'example.ru',
    $_POST,
    $_SERVER,
    'contact',
);

if ($verdict->isSpam()) {
    return new JsonResponse(['ok' => false, 'error' => 'spam_detected'], 400);
}
```

### Глобально через auto_prepend_file

Если обработчиков много, в PHP-FPM пул сайта добавляется
`auto_prepend_file = /var/www/lib/PHP-Form-Spam-Checker/integrations/auto-prepend.php`
и в конфиге сайта ставится `'auto' => true`. Guard сработает только на URI из
`match`; статика и админка не затрагиваются. Для пулов с тяжёлым API
включайте только после проверки `match`/`skip`.

## 3. Из Node / Go / Python (CLI-мост)

```bash
/opt/php85/bin/php /var/www/lib/PHP-Form-Spam-Checker/bin/spam-check \
  --form=register \
  --config=/var/www/lib/PHP-Form-Spam-Checker/config/sites/example.ru.php \
  --base64=BASE64_JSON
```

В STDOUT — один JSON-объект; коды выхода `0/1/2/3` (чисто / подозрительно /
спам / ошибка). Правила:

- `status = error` трактуйте как **fail open**: обработайте форму штатно;
- таймаут 2–5 секунд;
- STDOUT только JSON, диагностика — в STDERR.

Пример для Node: `examples/node/bridge.mjs`.

## HTTP-эндпоинт

`public/check.php` принимает POST JSON и возвращает вердикт. Защищается
заголовком `X-Spam-Checker-Key`, если задан `endpoint.key`. Ограничения:
не-POST → 405, кривой JSON → 400, неверный ключ → 403, большое тело → 413.

## Как проверить встраивание

1. Юнит-тест обвязки с `storage.driver = memory` и стабом контекста.
2. Отправить honeypot-полезную нагрузку: ожидается спам, письмо не уходит.
3. Отправить чистую заявку: ожидается одно нормальное письмо.
4. Сверить обе записи в журнале вердиктов.
5. В `shadow`-режиме убедиться, что спам всё ещё доходит до приложения (нет
   регрессии), и только потом включать `enforce`.
