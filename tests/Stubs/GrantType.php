<?php

declare(strict_types=1);

namespace LeagueTests\Stubs;

use DateInterval;
use Defuse\Crypto\Key;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\EventEmitting\EventEmitter;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\DeviceCodeResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

final class GrantType implements GrantTypeInterface
{
    private EventEmitter $emitter;

    public function setEmitter(EventEmitter $emitter): self
    {
        $this->emitter = $emitter;

        return $this;
    }

    public function getEmitter(): EventEmitter
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
    ): ResponseTypeInterface {
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

    public function setDefaultScope(string $scope): void
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

    public function canRespondToDeviceAuthorizationRequest(ServerRequestInterface $request): bool
    {
        return true;
    }

    public function completeDeviceAuthorizationRequest(string $deviceCode, UserEntityInterface $user, bool $userApproved): void
    {
    }

    public function respondToDeviceAuthorizationRequest(ServerRequestInterface $request): DeviceCodeResponse
    {
        return new DeviceCodeResponse();
    }

    public function setIntervalVisibility(bool $intervalVisibility): void
    {
    }

    public function getIntervalVisibility(): bool
    {
        return false;
    }

    public function setIncludeVerificationUriComplete(bool $includeVerificationUriComplete): void
    {
    }
}
