<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities\Traits;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

use function array_values;

trait TokenEntityTrait
{
    /**
     * @var ScopeEntityInterface[]
     */
    protected array $scopes = [];

    protected DateTimeImmutable $expiryDateTime;

    /**
     * @var non-empty-string|null
     */
    protected string|null $userIdentifier = null;

    protected ClientEntityInterface $client;

    /**
     * Associate a scope with the token.
     */
    public function addScope(ScopeEntityInterface $scope): void
    {
        $this->scopes[$scope->getIdentifier()] = $scope;
    }

    /**
     * Return an array of scopes associated with the token.
     *
     * @return ScopeEntityInterface[]
     */
    public function getScopes(): array
    {
        return array_values($this->scopes);
    }

    /**
     * Get the token's expiry date time.
     */
    public function getExpiryDateTime(): DateTimeImmutable
    {
        return $this->expiryDateTime;
    }

    /**
     * Set the date time when the token expires.
     */
    public function setExpiryDateTime(DateTimeImmutable $dateTime): void
    {
        $this->expiryDateTime = $dateTime;
    }

    /**
     * Set the identifier of the user associated with the token.
     *
     * @param non-empty-string $identifier The identifier of the user
     */
    public function setUserIdentifier(string $identifier): void
    {
        $this->userIdentifier = $identifier;
    }

    /**
     * Get the token user's identifier.
     *
     * @return non-empty-string|null
     */
    public function getUserIdentifier(): string|null
    {
        return $this->userIdentifier;
    }

    /**
     * Get the client that the token was issued to.
     */
    public function getClient(): ClientEntityInterface
    {
        return $this->client;
    }

    /**
     * Set the client that the token was issued to.
     */
    public function setClient(ClientEntityInterface $client): void
    {
        $this->client = $client;
    }
}
