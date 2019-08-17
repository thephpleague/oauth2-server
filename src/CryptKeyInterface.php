<?php
declare(strict_types=1);

namespace League\OAuth2\Server;

interface CryptKeyInterface
{
    /**
     * Retrieve key path.
     *
     * @return string
     */
    public function getKeyPath(): string;

    /**
     * Retrieve key pass phrase.
     *
     * @return null|string
     */
    public function getPassPhrase(): ?string;
}
