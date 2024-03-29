<?php

declare(strict_types=1);

namespace League\OAuth2\Server;

interface CryptKeyInterface
{
    /**
     * Retrieve key path.
     */
    public function getKeyPath(): string;

    /**
     * Retrieve key pass phrase.
     */
    public function getPassPhrase(): ?string;

    /**
     * Get key contents
     *
     * @return string Key contents
     */
    public function getKeyContents(): string;
}
