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
    public function getIdentifier(): string;

    public function setIdentifier(mixed $identifier): void;

    public function getExpiryDateTime(): DateTimeImmutable;

    public function setExpiryDateTime(DateTimeImmutable $dateTime): void;

    public function setUserIdentifier(string|int|null $identifier): void;

    public function getUserIdentifier(): string|int|null;

    public function getClient(): ClientEntityInterface;

    public function setClient(ClientEntityInterface $client): void;

    public function addScope(ScopeEntityInterface $scope): void;

    /**
     * @return ScopeEntityInterface[]
     */
    public function getScopes(): array;
}
