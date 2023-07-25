<?php

declare(strict_types=1);

namespace LeagueTests\Stubs;

use DateInterval;
use Defuse\Crypto\Key;
use League\Event\EmitterInterface;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

final class GrantType implements GrantTypeInterface
{
    private ?EmitterInterface $emitter;

    public function setEmitter(EmitterInterface $emitter = null): self
    {
        $this->emitter = $emitter;

        return $this;
    }

    public function getEmitter(): ?EmitterInterface
    {
        return $this->emitter;
    }

    public function setRefreshTokenTTL(DateInterval $refreshTokenTTL): void
    {
    }

    public function getIdentifier(): string
    {
        return 'grant_type_identifier';
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) {
        return $responseType;
    }

    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        return true;
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequest
    {
        $authRequest = new AuthorizationRequest();
        $authRequest->setGrantTypeId(self::class);

        return $authRequest;
    }

    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): BearerTokenResponse
    {
        return new BearerTokenResponse();
    }

    public function canRespondToAccessTokenRequest(ServerRequestInterface $request): bool
    {
        return true;
    }

    public function setClientRepository(ClientRepositoryInterface $clientRepository): void
    {
    }

    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository): void
    {
    }

    public function setScopeRepository(ScopeRepositoryInterface $scopeRepository): void
    {
    }

    public function setDefaultScope($scope): void
    {
    }

    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
    }

    public function setEncryptionKey(Key|string|null $key = null): void
    {
    }

    public function revokeRefreshTokens(bool $willRevoke): void
    {
    }
}
