<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server;

use DateInterval;
use Defuse\Crypto\Key;
use League\OAuth2\Server\EventEmitting\EmitterAwareInterface;
use League\OAuth2\Server\EventEmitting\EmitterAwarePolyfill;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationServer implements EmitterAwareInterface
{
    use EmitterAwarePolyfill;

    /**
     * @var GrantTypeInterface[]
     */
    protected array $enabledGrantTypes = [];

    /**
     * @var DateInterval[]
     */
    protected array $grantTypeAccessTokenTTL = [];

    protected CryptKeyInterface $privateKey;

    protected CryptKeyInterface $publicKey;

    protected ResponseTypeInterface $responseType;

    private string|Key $encryptionKey;

    private string $defaultScope = '';

    private bool $revokeRefreshTokens = true;

    /**
     * New server instance
     */
    public function __construct(
        private ClientRepositoryInterface $clientRepository,
        private AccessTokenRepositoryInterface $accessTokenRepository,
        private ScopeRepositoryInterface $scopeRepository,
        CryptKeyInterface|string $privateKey,
        Key|string $encryptionKey,
        ResponseTypeInterface|null $responseType = null
    ) {
        if ($privateKey instanceof CryptKeyInterface === false) {
            $privateKey = new CryptKey($privateKey);
        }

        $this->privateKey = $privateKey;
        $this->encryptionKey = $encryptionKey;

        if ($responseType === null) {
            $responseType = new BearerTokenResponse();
        } else {
            $responseType = clone $responseType;
        }

        $this->responseType = $responseType;
    }

    /**
     * Enable a grant type on the server
     */
    public function enableGrantType(GrantTypeInterface $grantType, DateInterval|null $accessTokenTTL = null): void
    {
        if ($accessTokenTTL === null) {
            $accessTokenTTL = new DateInterval('PT1H');
        }

        $grantType->setAccessTokenRepository($this->accessTokenRepository);
        $grantType->setClientRepository($this->clientRepository);
        $grantType->setScopeRepository($this->scopeRepository);
        $grantType->setDefaultScope($this->defaultScope);
        $grantType->setPrivateKey($this->privateKey);
        $grantType->setEmitter($this->getEmitter());
        $grantType->setEncryptionKey($this->encryptionKey);
        $grantType->revokeRefreshTokens($this->revokeRefreshTokens);

        $this->enabledGrantTypes[$grantType->getIdentifier()] = $grantType;
        $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()] = $accessTokenTTL;
    }

    /**
     * Validate an authorization request
     *
     * @throws OAuthServerException
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                return $grantType->validateAuthorizationRequest($request);
            }
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Complete an authorization request
     */
    public function completeAuthorizationRequest(
        AuthorizationRequestInterface $authRequest,
        ResponseInterface $response
    ): ResponseInterface {
        return $this->enabledGrantTypes[$authRequest->getGrantTypeId()]
            ->completeAuthorizationRequest($authRequest)
            ->generateHttpResponse($response);
    }

    /**
     * Respond to device authorization request
     *
     * @throws OAuthServerException
     */
    public function respondToDeviceAuthorizationRequest(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToDeviceAuthorizationRequest($request)) {
                return $grantType
                    ->respondToDeviceAuthorizationRequest($request)
                    ->generateHttpResponse($response);
            }
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Complete a device authorization request
     */
    public function completeDeviceAuthorizationRequest(string $deviceCode, string $userId, bool $userApproved): void
    {
        $this->enabledGrantTypes['urn:ietf:params:oauth:grant-type:device_code']
          ->completeDeviceAuthorizationRequest($deviceCode, $userId, $userApproved);
    }

    /**
     * Return an access token response.
     *
     * @throws OAuthServerException
     */
    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        foreach ($this->enabledGrantTypes as $grantType) {
            if (!$grantType->canRespondToAccessTokenRequest($request)) {
                continue;
            }

            $tokenResponse = $grantType->respondToAccessTokenRequest(
                $request,
                $this->getResponseType(),
                $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()]
            );

            return $tokenResponse->generateHttpResponse($response);
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Get the token type that grants will return in the HTTP response.
     */
    protected function getResponseType(): ResponseTypeInterface
    {
        $responseType = clone $this->responseType;

        if ($responseType instanceof AbstractResponseType) {
            $responseType->setPrivateKey($this->privateKey);
        }

        $responseType->setEncryptionKey($this->encryptionKey);

        return $responseType;
    }

    /**
     * Set the default scope for the authorization server.
     */
    public function setDefaultScope(string $defaultScope): void
    {
        $this->defaultScope = $defaultScope;
    }

    /**
     * Sets whether to revoke refresh tokens or not (for all grant types).
     */
    public function revokeRefreshTokens(bool $revokeRefreshTokens): void
    {
        $this->revokeRefreshTokens = $revokeRefreshTokens;
    }
}
