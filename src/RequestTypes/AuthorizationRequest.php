<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\RequestTypes;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;

class AuthorizationRequest implements AuthorizationRequestInterface
{
    /**
     * The grant type identifier
     *
     * @var string
     */
    protected $grantTypeId;

    /**
     * The client identifier
     *
     * @var ClientEntityInterface
     */
    protected $client;

    /**
     * The user identifier
     *
     * @var UserEntityInterface
     */
    protected $user;

    /**
     * An array of scope identifiers
     *
     * @var ScopeEntityInterface[]
     */
    protected $scopes = [];

    /**
     * Has the user authorized the authorization request
     *
     * @var bool
     */
    protected $authorizationApproved = false;

    /**
     * The redirect URI used in the request
     *
     * @var string|null
     */
    protected $redirectUri;

    /**
     * The state parameter on the authorization request
     *
     * @var string|null
     */
    protected $state;

    /**
     * The code challenge (if provided)
     *
     * @var string
     */
    protected $codeChallenge;

    /**
     * The code challenge method (if provided)
     *
     * @var string
     */
    protected $codeChallengeMethod;

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

    public function getUser(): ?UserEntityInterface
    {
        return $this->user;
    }

    public function setUser(UserEntityInterface $user): void
    {
        $this->user = $user;
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

    public function isAuthorizationApproved(): bool
    {
        return $this->authorizationApproved;
    }

    public function setAuthorizationApproved(bool $authorizationApproved): void
    {
        $this->authorizationApproved = $authorizationApproved;
    }

    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    public function setRedirectUri(?string $redirectUri): void
    {
        $this->redirectUri = $redirectUri;
    }

    public function getState(): ?string
    {
        return $this->state;
    }

    public function setState(string $state): void
    {
        $this->state = $state;
    }

    public function getCodeChallenge(): ?string
    {
        return $this->codeChallenge;
    }

    public function setCodeChallenge(string $codeChallenge): void
    {
        $this->codeChallenge = $codeChallenge;
    }

    public function getCodeChallengeMethod(): ?string
    {
        return $this->codeChallengeMethod;
    }

    public function setCodeChallengeMethod(string $codeChallengeMethod): void
    {
        $this->codeChallengeMethod = $codeChallengeMethod;
    }
}
