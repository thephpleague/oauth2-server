<?php

declare(strict_types=1);

namespace LeagueTests\Stubs;

use DateInterval;
use League\Event\EmitterInterface;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

final class GrantType implements GrantTypeInterface
{
    private $emitter;

    public function setEmitter(?EmitterInterface $emitter = null)
    {
        $this->emitter = $emitter;

        return $this;
    }

    public function getEmitter()
    {
        return $this->emitter;
    }

    public function setRefreshTokenTTL(DateInterval $refreshTokenTTL)
    {
    }

    public function getIdentifier()
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

    public function canRespondToAuthorizationRequest(ServerRequestInterface $request)
    {
        return true;
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request)
    {
        $authRequest = new AuthorizationRequest();
        $authRequest->setGrantTypeId(self::class);

        return $authRequest;
    }

    public function completeAuthorizationRequest(AuthorizationRequest $authorizationRequest)
    {
    }

    public function canRespondToAccessTokenRequest(ServerRequestInterface $request)
    {
        return true;
    }

    public function setClientRepository(ClientRepositoryInterface $clientRepository)
    {
    }

    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository)
    {
    }

    public function setScopeRepository(ScopeRepositoryInterface $scopeRepository)
    {
    }

    public function setDefaultScope($scope)
    {
    }

    public function setPrivateKey(CryptKey $privateKey)
    {
    }

    public function setEncryptionKey($key = null)
    {
    }
}
