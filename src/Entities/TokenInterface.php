<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

use DateTimeImmutable;

interface TokenInterface
{
    /**
     * Get the token's identifier.
     *
     * @return string
     */
    public function getIdentifier();

    /**
     * Set the token's identifier.
     */
    public function setIdentifier(mixed $identifier): void;

    /**
     * Get the token's expiry date time.
     *
     * @return DateTimeImmutable
     */
    public function getExpiryDateTime();

    /**
     * Set the date time when the token expires.
     */
    public function setExpiryDateTime(DateTimeImmutable $dateTime): void;

    /**
     * Set the identifier of the user associated with the token.
     */
    public function setUserIdentifier(string|int|null $identifier): void;

    /**
     * Get the token user's identifier.
     */
    public function getUserIdentifier(): string|int|null;

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
    public function getScopes();
}
