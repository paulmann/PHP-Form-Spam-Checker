<?php

declare(strict_types=1);

/**
 * Bayesian classifier — programmatic training and scoring example.
 *
 * Run:  php examples/bayes-train.php
 *
 * This is the same model the pipeline uses (`bayes.enabled = true`). Training
 * is normally done out of process with:
 *
 *   php bin/spam-train --config=/etc/spam.php --ham=ham.txt --spam=spam.txt
 *   php bin/spam-train --config=/etc/spam.php --stats
 *
 * This example shows the equivalent in code, plus how a fresh process reloads
 * the persisted model. It is offline and writes only to the system temp dir.
 * The model stores token counts — never the training documents.
 */

use FormSpamChecker\Bayes\CacheModelStorage;
use FormSpamChecker\Bayes\Classifier;
use FormSpamChecker\Cache\FileCache;

require dirname(__DIR__) . '/autoload.php';

// The model is one JSON value in a CacheInterface; bayes.storage_path would
// namespace it in a real configuration.
$cache = new FileCache(sys_get_temp_dir() . '/php-form-spam-checker-bayes/cache');
$storage = new CacheModelStorage($cache);

$classifier = new Classifier($storage, minDocuments: 4, threshold: 0.92);

// ---------------------------------------------------------------- training
// One document per line in the CLI; a string per document here.
$ham = [
    'Нужен отчёт по поверке прибора, счётчик воды.',
    'Прошу перезвонить по поводу договора на обслуживание.',
    'Подскажите цену и сроки поставки, пожалуйста.',
    'Хочу записаться на консультацию в филиале.',
];

$spam = [
    'casino bitcoin payday loan free money click here',
    'buy backlinks seo package guest post cheap',
    'viagra cialis pharmacy replica watches',
    'Заработок без вложений, займ онлайн, пробить по базе.',
];

$classifier->trainFromList($ham, false);
$classifier->trainFromList($spam, true);
$classifier->persist();

echo "trained documents: {$classifier->documentCount()}\n";
echo "vocabulary:        {$classifier->vocabularySize()}\n";
echo "tokens:            {$classifier->tokenCount()}\n";
echo "is trained:        " . ($classifier->isTrained() ? 'yes' : 'no') . "\n\n";

// ------------------------------------------------- a fresh process / request
// The pipeline builds the classifier per request (SpamChecker::defaultChecks)
// and the model is loaded lazily from the cache.
$reloaded = new Classifier(new CacheModelStorage($cache), minDocuments: 4, threshold: 0.92);

$samples = [
    'legit' => 'Прошу перезвонить по поводу договора на обслуживание.',
    'spam' => 'casino bitcoin payday loan free money click here',
    'mixed' => 'Заработок без вложений и биткоин, пишите.',
];

foreach ($samples as $label => $text) {
    $probability = $reloaded->score($text);

    printf(
        "%-6s P(spam)=%.3f  >= threshold(%.2f): %s\n",
        $label,
        $probability,
        $reloaded->threshold(),
        $probability >= $reloaded->threshold() ? 'yes' : 'no',
    );
}

// ---------------------------------------------------------------- in pipeline
// BayesCheck reads the already form-scoped configuration:
//
//   'bayes' => [
//       'enabled' => true,
//       'threshold' => 0.92,      // spam probability that scores
//       'min_documents' => 20,    // below this the model abstains
//       'score_scale' => 100,     // score = round(P * 100)
//       'hard' => false,          // true: a match becomes a hard SPAM
//   ],
//
// and turns P(spam) >= threshold into a suspicion by default. The model lives
// where `bayes.storage_path` points (file cache: <storage.path>/cache/<hash>.json).
// Privacy: only token counts are stored; training texts never leave the process.
