<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\RequestTypes;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

class DeviceAuthorizationRequest
{
    /**
     * The grant type identifier
     *
     */
    protected string $grantTypeId;

    /**
     * The client identifier
     *
     */
    protected ClientEntityInterface $client;

    private bool $authorizationApproved;

    private string $userCode;

    private string|int $userIdentifier;

    /**
     * An array of scope identifiers
     *
     * @var ScopeEntityInterface[]
     */
    protected array $scopes = [];

    public function getGrantTypeId(): string
    {
        return $this->grantTypeId;
    }

    public function setGrantTypeId(string $grantTypeId): void
    {
        $this->grantTypeId = $grantTypeId;
    }

    public function getClient(): ClientEntityInterface
    {
        return $this->client;
    }

    public function setClient(ClientEntityInterface $client): void
    {
        $this->client = $client;
    }

    /**
     * @return ScopeEntityInterface[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function setScopes(array $scopes): void
    {
        $this->scopes = $scopes;
    }

    public function getUserCode(): string
    {
        return $this->userCode;
    }

    public function getUserIdentifier(): string|int
    {
        return $this->userIdentifier;
    }

    public function authorizationApproved(): bool
    {
        return $this->authorizationApproved;
    }
}
