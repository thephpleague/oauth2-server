<?php

namespace League\OAuth2\Server;

interface CryptKeyInterface
{
    /**
     * Retrieve key path.
     *
     * @return string
     */
    public function getKeyPath();

    /**
     * Retrieve key pass phrase.
     *
     * @return null|string
     */
    public function getPassPhrase();

    /**
     * Get key contents
     *
     * @return string Key contents
     */
    public function getKeyContents(): string;
}
