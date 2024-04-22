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

interface TokenInterface
{
    /**
     * Get the token's identifier.
     *
     * @return non-empty-string
     */
    public function getIdentifier(): string;

    /**
     * Set the token's identifier.
     *
     * @param non-empty-string $identifier
     */
    public function setIdentifier(string $identifier): void;

    /**
     * Get the token's expiry date time.
     */
    public function getExpiryDateTime(): DateTimeImmutable;

    /**
     * Set the date time when the token expires.
     */
    public function setExpiryDateTime(DateTimeImmutable $dateTime): void;

    /**
     * Set the identifier of the user associated with the token.
     *
     * @param non-empty-string $identifier
     */
    public function setUserIdentifier(string $identifier): void;

    /**
     * Get the token user's identifier.
     *
     * @return non-empty-string|null
     */
    public function getUserIdentifier(): string|null;

    /**
     * Get the client that the token was issued to.
     */
    public function getClient(): ClientEntityInterface;

    /**
     * Set the client that the token was issued to.
     */
    public function setClient(ClientEntityInterface $client): void;

    /**
     * Associate a scope with the token.
     */
    public function addScope(ScopeEntityInterface $scope): void;

    /**
     * Return an array of scopes associated with the token.
     *
     * @return ScopeEntityInterface[]
     */
    public function getScopes(): array;
}
