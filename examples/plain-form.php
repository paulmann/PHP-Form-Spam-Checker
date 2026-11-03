<?php

declare(strict_types=1);

/**
 * Plain PHP form demo — copy this pattern into any PHP form.
 *
 * Run:  php -S 127.0.0.1:8080 examples/plain-form.php
 * Open: http://127.0.0.1:8080/
 *
 * The demo never sends e-mail: it shows the verdict the checker produced.
 */

use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\FormProtector;
use FormSpamChecker\SpamChecker;

require dirname(__DIR__) . '/autoload.php';

$config = Config::fromArray([
    'time_trap' => [
        'enabled' => true,
        // Demo secret; use SPAM_CHECKER_SECRET in a real application.
        'secret' => 'demo-secret-do-not-use-in-production',
    ],
    'storage' => [
        'driver' => 'file',
        'path' => sys_get_temp_dir() . '/php-form-spam-checker-demo',
    ],
    'log' => [
        'enabled' => true,
        'path' => sys_get_temp_dir() . '/php-form-spam-checker-demo/verdicts.jsonl',
        'pii' => true,
    ],
]);

$checker = new SpamChecker($config);
$protector = new FormProtector($checker, $config);

$verdict = null;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $verdict = $protector->verify($_POST, 'contact', Context::fromGlobals());

    if ($verdict->isSpam()) {
        http_response_code(400);
        echo '<!doctype html><meta charset="utf-8"><h1>Заявка отклонена</h1>';
        echo '<p>Форма посчитала сообщение спамом. Причина: '
            . htmlspecialchars(implode('; ', $verdict->reasons()), ENT_QUOTES, 'UTF-8') . '</p>';
        echo '<p><a href="/">Вернуться</a></p>';
        exit;
    }
}

header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>PHP Form Spam Checker — demo</title>
    <style>
        body { font: 16px/1.5 system-ui, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px; }
        label { display: block; margin: 12px 0 4px; font-weight: 600; }
        input, textarea { width: 100%; box-sizing: border-box; padding: 8px; }
        textarea { min-height: 110px; }
        button { margin-top: 16px; padding: 10px 18px; }
        .verdict { background: #f2f7ff; border: 1px solid #c9dcff; padding: 12px; border-radius: 8px; margin-top: 24px; }
        .clean { border-color: #b7e4c7; background: #f0fff4; }
    </style>
</head>
<body>
<h1>Демо-форма обратной связи</h1>

<?php if ($verdict !== null): ?>
    <div class="verdict <?= $verdict->isClean() ? 'clean' : '' ?>">
        <strong>Вердикт:</strong> <?= htmlspecialchars($verdict->status->value, ENT_QUOTES, 'UTF-8') ?>
        (score <?= $verdict->score ?>)<br>
        <?php if ($verdict->reasons() !== []): ?>
            <strong>Причины:</strong>
            <?= htmlspecialchars(implode('; ', $verdict->reasons()), ENT_QUOTES, 'UTF-8') ?>
        <?php else: ?>
            Проверки не нашли признаков спама — заявка была бы принята.
        <?php endif; ?>
    </div>
<?php endif; ?>

<form method="post" action="">
    <?= $protector->fields('contact') ?>

    <label for="name">Имя</label>
    <input id="name" name="name" required>

    <label for="email">E-mail</label>
    <input id="email" name="email" type="email" required>

    <label for="message">Сообщение</label>
    <textarea id="message" name="message" required></textarea>

    <button type="submit">Отправить</button>
</form>

<p><small>Откройте исходный код страницы, чтобы увидеть поля, которые добавляет
<code>FormProtector::fields()</code>: honeypot и подписанный токен времени.</small></p>
</body>
</html>
