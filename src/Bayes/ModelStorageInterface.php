<?php

declare(strict_types=1);

namespace FormSpamChecker\Bayes;

/**
 * Persistence port for the Bayesian model.
 *
 * Implementations must be atomic on save (a reader sees either the old or the
 * new model, never a partial one) and must return null when nothing has been
 * stored yet or the stored payload is unreadable.
 */
interface ModelStorageInterface
{
    /**
     * Load the last saved model, or null when none is available.
     */
    public function load(): ?Model;

    /**
     * Persist the model atomically, replacing any previous one.
     */
    public function save(Model $model): void;

    /**
     * Remove the persisted model, if any.
     */
    public function delete(): void;
}
