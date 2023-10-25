<?php

/**
 * @author      Patrick Rodacker <dev@rodacker.de>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\RequestTypes;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;

interface AuthorizationRequestInterface
{
    public function getUser(): UserEntityInterface|null;

    public function setState(string $state): void;

    public function getClient(): ClientEntityInterface;

    public function setAuthorizationApproved(bool $authorizationApproved): void;

    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function setScopes(array $scopes): void;

    public function setRedirectUri(?string $redirectUri): void;

    public function getRedirectUri(): ?string;

    public function getCodeChallengeMethod(): ?string;

    public function setGrantTypeId(string $grantTypeId): void;

    public function setUser(UserEntityInterface $user): void;

    public function setClient(ClientEntityInterface $client): void;

    public function setCodeChallenge(string $codeChallenge): void;

    public function isAuthorizationApproved(): bool;

    public function getState(): ?string;

    public function getCodeChallenge(): ?string;

    public function setCodeChallengeMethod(string $codeChallengeMethod): void;

    /**
     * @return ScopeEntityInterface[]
     */
    public function getScopes(): array;

    public function getGrantTypeId(): string;
}
