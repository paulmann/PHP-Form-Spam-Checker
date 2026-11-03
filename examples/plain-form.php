<?php

declare(strict_types=1);

/**
 * Plain PHP form — 2.0 pipeline demo. Copy this pattern into any PHP form.
 *
 * Run:  php -S 127.0.0.1:8080 examples/plain-form.php
 * Open: http://127.0.0.1:8080/
 *
 * The demo never sends e-mail: it shows the verdict the pipeline produced,
 * including every executed check with its status, score and reason.
 *
 * It is self-contained (bundled autoload.php, no vendor/ required) and uses
 * only local checks. Network checks stay disabled, so the demo makes no
 * outbound requests.
 *
 * Demo only: run it on a local or staging copy — it uses a demo secret and
 * writes to the system temp directory. Never point it at a production config.
 */

use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\FormProtector;
use FormSpamChecker\SpamChecker;

require dirname(__DIR__) . '/autoload.php';

// Demo secrets: use SPAM_CHECKER_SECRET (>= 16 chars) in a real application.
$secret = 'demo-secret-change-me-0123456789';
$stateDir = sys_get_temp_dir() . '/php-form-spam-checker-demo';

$config = Config::fromArray([
    'thresholds' => [
        'suspicious' => 30,
        'spam' => 60,
    ],

    // Kept off in the demo: the page is served fresh on every request.
    'time_trap' => [
        'enabled' => false,
    ],

    // Behavioural layer: dynamic honeypot + JS challenge, both HMAC-signed.
    'behavioral' => [
        'honeypot' => [
            'dynamic' => true,
            'secret' => $secret,
            'missing_score' => 10,
        ],
        'js_challenge' => [
            'enabled' => true,
            'secret' => $secret,
            'missing_score' => 15,
        ],
    ],

    // Network checks are intentionally off in the demo.
    'abuseipdb' => ['enabled' => false],
    'dnsbl' => ['enabled' => false],
    'spf' => ['enabled' => false],
    'dmarc' => ['enabled' => false],
    'bayes' => ['enabled' => false],
    'waf' => ['enabled' => false],

    'storage' => [
        'driver' => 'file',
        'path' => $stateDir,
    ],
    'cache' => [
        'driver' => 'file',
        'path' => $stateDir . '/cache',
    ],
    'log' => [
        'enabled' => true,
        'path' => $stateDir . '/verdicts.jsonl',
        'pii' => true,
    ],
]);

$checker = new SpamChecker($config);
$protector = new FormProtector($checker, $config);

$verdict = null;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    // 2.0-native call: build the request snapshot and run the pipeline.
    $request = RequestData::fromGlobals($_SERVER, $_POST, 'contact');
    $verdict = $checker->checkRequest($request);

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
    <title>PHP Form Spam Checker 2.0 — demo</title>
    <style>
        body { font: 16px/1.5 system-ui, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 16px; }
        label { display: block; margin: 12px 0 4px; font-weight: 600; }
        input, textarea { width: 100%; box-sizing: border-box; padding: 8px; }
        textarea { min-height: 110px; }
        button { margin-top: 16px; padding: 10px 18px; }
        .verdict { background: #f2f7ff; border: 1px solid #c9dcff; padding: 12px; border-radius: 8px; margin-top: 24px; }
        .clean { border-color: #b7e4c7; background: #f0fff4; }
        .checks { margin: 8px 0 0; padding-left: 18px; font-size: 14px; }
        .checks li { margin: 2px 0; }
        .check-spam { color: #b42318; font-weight: 600; }
        .check-ham { color: #475467; }
        .muted { color: #667085; }
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

        <strong>Все проверки конвейера:</strong>
        <ul class="checks">
            <?php foreach ($verdict->outcomes as $outcome): ?>
                <li class="check-<?= htmlspecialchars($outcome->status->value, ENT_QUOTES, 'UTF-8') ?>">
                    <code><?= htmlspecialchars($outcome->check, ENT_QUOTES, 'UTF-8') ?></code>
                    — <?= htmlspecialchars($outcome->status->value, ENT_QUOTES, 'UTF-8') ?>
                    (score <?= $outcome->score ?>)
                    <?php if ($outcome->reason !== ''): ?>
                        <span class="muted"><?= htmlspecialchars($outcome->reason, ENT_QUOTES, 'UTF-8') ?></span>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ul>
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

<p><small>Откройте исходный код страницы: <code>FormProtector::fields()</code>
добавляет динамическую приманку (<code>_hp_…</code>), и, если включён
<code>behavioral.js_challenge</code>, — поля JS-челленджа и inline-скрипт.
Заявки пишутся в <code><?= htmlspecialchars($stateDir, ENT_QUOTES, 'UTF-8') ?>/verdicts.jsonl</code>.</small></p>
</body>
</html>
