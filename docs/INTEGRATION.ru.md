# Встраивание: практическое руководство

Пять способов использования, от простого к «серверному». Все они делят один
`FormSpamChecker\Config`, одну модель вердикта и один конфиг сайта.

- [1. Внутри PHP-формы](#1-внутри-php-формы)
- [2. Общий модуль на сервере](#2-общий-модуль-на-сервере)
- [3. WAF на весь сайт](#3-waf-на-весь-сайт)
- [4. Из Node / Go / Python (CLI-мосты)](#4-из-node--go--python-cli-мосты)
- [5. HTTP-эндпоинт](#5-http-эндпоинт)
- [Обучение байесовской модели](#обучение-байесовской-модели)
- [Как проверить встраивание](#как-проверить-встраивание)

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
    'time_trap' => ['enabled' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
    'behavioral' => [
        'honeypot' => ['dynamic' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
    ],
]);

$checker = new SpamChecker($config);
$protector = new FormProtector($checker, $config);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $verdict = $protector->verify($_POST, 'contact', Context::fromGlobals());

    if ($verdict->isSpam()) {
        http_response_code(400);
        exit('Заявка отклонена антиспам-проверкой.');
    }

    // Вердикт suspicious здесь намеренно не блокирует: посмотрите
    // $verdict->reasons() и решите, нужна ли модерация.
}
?>
<form method="post">
    <?= $protector->fields('contact') /* honeypot + токен + JS-челлендж */ ?>
    <input name="email" type="email" required>
    <textarea name="message" required></textarea>
    <button type="submit">Отправить</button>
</form>
```

Замечания:

- `verify()` / `verifyRequest()` вызывайте **до** отправки письма и записи в БД.
- `FormProtector::fields()` должен находиться внутри `<form>`.
- Нативный вызов 2.0: соберите `FormSpamChecker\Data\RequestData` и передайте
  его в `SpamChecker::checkRequest()`:

  ```php
  use FormSpamChecker\Data\RequestData;

  $request = RequestData::fromGlobals($_SERVER, $_POST, 'contact');
  $verdict = $checker->checkRequest($request);
  ```

- Упавшая проверка записывается как `error` и не блокирует форму: сбой
  журналирования или сети не ломает обработчик.

## 2. Общий модуль на сервере

Рекомендуется, когда на одном сервере много сайтов и обновление не должно
трогать каждый docroot.

Раскладка:

```text
/var/www/lib/PHP-Form-Spam-Checker/
├── autoload.php
├── src/
├── bin/spam-check          # вердикт формы для не-PHP бэкендов
├── bin/waf-check           # вердикт WAF для не-PHP бэкендов
├── bin/spam-train          # обучение байесовской модели
├── integrations/guard.php  # drop-in формы
├── integrations/waf.php    # drop-in WAF
├── integrations/auto-prepend.php
├── config/sites/<host>.php
├── var/sites/<host>/        # счётчики
└── var/log/                 # журналы вердиктов: <host>.jsonl
```

Установка/обновление (root):

```bash
deploy/install-shared.sh /path/to/checkout
deploy/init-site-state.sh example.ru www-example   # владелец состояния сайта
```

В обработчик формы, **до** чтения входных данных, добавляется одна строка:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

`guard.php` запускает два слоя по порядку:

1. **WAF** — только если в конфиге сайта выставлен `waf.enabled`: проверяет
   весь запрос (URI, query, тело, заголовки, cookies, метод, размер);
2. **конвейер формы** (`off` / `shadow` / `enforce`).

Оба слоя пропускают всё, что не подходит под их конфиг, и любой внутренний
сбой трактуется как fail open. Сайту с `guard.php` не нужен дополнительный
`integrations/waf.php` — файрвол уже внутри guard.

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
        'behavioral' => [
            'honeypot' => ['dynamic' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
        ],
        'log' => ['enabled' => true],
    ],
];
```

Порядок внедрения:

1. `mode = shadow` на 1–3 дня: всё пишется в журнал, сайт ведёт себя как раньше.
2. Смотрим `var/log/<host>.jsonl`, правим конфиг по ложным срабатываниям.
3. Переключаем `mode = enforce`: спам получает HTTP 400, приложение его не
   видит. `response = silent` возвращает HTTP 200 с пустым телом.

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

`evaluateFor()` никогда не завершает скрипт: она всегда вычисляет вердикт и
возвращает его вызывающему коду.

### Глобально через auto_prepend_file

Если обработчиков много, в PHP-FPM пул сайта добавляется
`auto_prepend_file = /var/www/lib/PHP-Form-Spam-Checker/integrations/auto-prepend.php`
и в конфиге сайта ставится `'auto' => true`. Guard формы сработает только на
URI из `match`; статика и админка не затрагиваются.

WAF внутри `auto-prepend.php` работает **независимо от legacy-флага `auto`**:
если выставлен `waf.enabled`, файрвол защищает каждый запрос, а конвейер формы
остаётся ограниченным эндпоинтами форм. Для пулов с тяжёлым API включайте
только после проверки `match`/`skip` и `waf_match`.

## 3. WAF на весь сайт

WAF проверяет каждый HTTP-запрос, а не только отправку формы. Оба слоя живут
в одном модуле и разворачиваются двумя способами:

- **`integrations/guard.php`** — guard формы; уже запускает WAF первым, если
  выставлен `waf.enabled`. Нужен сайту, где есть обработчик формы;
- **`integrations/waf.php`** — только файрвол; нужен сайту без guard формы или
  когда WAF ставится в один фронт-контроллер.

На один запрос подключайте **один** из них: `waf.php` поверх `guard.php`
проверит запрос дважды. Оба читают один `config/sites/<host>.php` (секция `waf`
внутри `config` плюс необязательные ключи верхнего уровня):

```php
// config/sites/example.ru.php — сначала monitor
return [
    'site' => 'example.ru',
    'mode' => 'enforce',
    'waf_mode' => 'monitor',              // off | monitor | block
    'waf_response' => 'auto',             // auto | json | html | silent
    'config' => [
        'waf' => [
            'enabled' => true,
            'mode' => 'monitor',
            'rules' => ['ip_reputation' => false, 'rate_limit' => false],
        ],
    ],
];
```

```php
// сайт без guard формы — только файрвол:
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php';

// сайт с формами — guard запускает WAF и конвейер формы, одно подключение:
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

Заблокированный запрос до конвейера формы уже не доходит. Правила, режимы и
ответы: [WAF.md](WAF.md).

## 4. Из Node / Go / Python (CLI-мосты)

### Вердикт формы: `bin/spam-check`

```bash
php bin/spam-check --config=/etc/spam.php --form=register --base64=BASE64_JSON
```

В STDOUT — один JSON-объект; коды выхода `0` — чисто, `1` — подозрительно,
`2` — спам, `3` — ошибка.

2.0: форма верхнего уровня и коды выхода не изменились, но
`checks[].status` теперь `spam|ham|uncertain|error` (в 1.x было
`clean|suspicious|spam`). Подробности: [MIGRATION-1-to-2.md](MIGRATION-1-to-2.md).

### Вердикт WAF: `bin/waf-check`

```bash
php bin/waf-check --config=/etc/spam.php \
  --json='{"method":"POST","uri":"/api/lead","ip":"203.0.113.10",
           "headers":{"host":"example.ru","content-type":"application/json"},
           "body":"{}","fields":{},"form":"lead"}'
```

Ответ: `{"blocked":bool,"status":"clean|suspicious|blocked","score":int,
"findings":[…],"reasons":[…]}`; коды выхода `0` — пропустить, `2` — блок,
`3` — ошибка; выключенный WAF отвечает `status: "disabled"`. Всегда передавайте
заголовки `host` и `content-type`: правило `protocol` начисляет за их
отсутствие баллы (мягкие). Полный формат: [WAF.md](WAF.md).

### Node-мост

`examples/node/bridge.mjs` — тот же приём, что в продакшене Astro-сайта; он
оборачивает оба моста:

```js
import { checkSpam } from "./bridge.mjs";

const verdict = await checkSpam("register", fields, {
  ip: request.ip,
  userAgent: request.headers["user-agent"],
  page: "/register/",
});

if (verdict.status === "spam") {
  // отклонить без подробностей
}
```

```bash
node examples/node/bridge.mjs register
```

Правила для моста:

- `status = error` (и отсутствие ответа) трактуйте как **fail open**:
  обработайте форму штатно и залогируйте ошибку;
- таймаут 2–5 секунд: проверка локальная и CPU-bound;
- STDOUT только JSON, диагностика — в STDERR и с кодом 3.

## 5. HTTP-эндпоинт

`public/check.php` принимает POST JSON и возвращает вердикт:

```bash
curl -s -X POST https://example.ru/check.php \
  -H 'Content-Type: application/json' \
  -H 'X-Spam-Checker-Key: ...' \
  -d '{"form":"contact","fields":{"email":"a@b.c"},"context":{"ip":"203.0.113.1","userAgent":"..."}}'
```

Ответ: `{"form":"contact","status":"clean","score":0,"reasons":[],"checks":[...]}`.
Коды: 400 — кривой JSON, 403 — неверный ключ, 405 — не POST, 413 — большое
тело, 500 — ошибка проверки.

Эндпоинт stateless, его безопасно держать на внутреннем интерфейсе или
localhost. Присланные поля он не возвращает. Ключ задаётся в `endpoint.key` и
передаётся в заголовке `X-Spam-Checker-Key` (сравнение за постоянное время).

## Обучение байесовской модели

`bayes` по умолчанию выключен и «молчит», пока в модели не наберётся
`bayes.min_documents` (20) документов:

```bash
php bin/spam-train --config=/etc/spam.php \
    --ham=/etc/spam/ham.txt --spam=/etc/spam/spam.txt

php bin/spam-train --config=/etc/spam.php \
    --text-spam="casino bitcoin payday loan" \
    --text-ham="нужен отчёт по поверке прибора"

php bin/spam-train --config=/etc/spam.php --stats
php bin/spam-train --config=/etc/spam.php --reset
```

Обучающие данные — обычный текст: один документ на строку, пустые строки и
строки с `#` пропускаются, несколько файлов можно перечислить через запятую.
Модель хранит только счётчики токенов (не исходные тексты) и пишется через
настроенный кэш (`bayes.storage_path` задаёт пространство имён модели).
Обучение офлайн, наружу ничего не уходит.

Автоматической обратной связи из конвейера нет: переобучайте модель по мере
накопления ham/spam-примеров и держите `bayes.hard` выключенным, пока не
проверите модель на реальном трафике.

## Как проверить встраивание

1. Юнит-тест обвязки с `storage.driver = memory`, `cache.driver = memory` и
   стабом контекста (без сети и файловой системы).
2. Отправить honeypot-полезную нагрузку: ожидается спам, письмо не уходит.
3. Отправить чистую заявку: ожидается одно нормальное письмо.
4. Сверить обе записи в журнале вердиктов.
5. В `shadow`-режиме убедиться, что спам всё ещё доходит до приложения (нет
   регрессии), и только потом включать `enforce`.
6. Для WAF сутки погонять `monitor` и сравнить записанные вердикты с вердиктами
   формы, прежде чем включать `block`.

Примеры из `examples/` запускайте только на локальной или staging-копии: в них
демо-секреты и системный temp-каталог, их нельзя направлять на боевой конфиг
или состояние продакшена.
