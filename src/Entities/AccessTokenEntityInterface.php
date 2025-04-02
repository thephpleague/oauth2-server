<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities;

use DateTimeImmutable;
use League\OAuth2\Server\CryptKeyInterface;

interface AccessTokenEntityInterface extends TokenInterface
{
    /**
     * Set a private key used to encrypt the access token.
     */
    public function setPrivateKey(CryptKeyInterface $privateKey): void;

    /**
     * Set a datetime value for the issued at value.
     */
    public function setIssuedAt(DateTimeImmutable $issuedAt): void;

    /**
     * Get the issued at datetime value. 
     */
    public function getIssuedAt(): ?DateTimeImmutable;

    /**
     * Generate a string representation of the access token.
     */
    public function toString(): string;
}
