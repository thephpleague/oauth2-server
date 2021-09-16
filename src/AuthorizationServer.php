<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use DateInterval;
use Defuse\Crypto\Key;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationServer implements EmitterAwareInterface
{
    use EmitterAwareTrait;

    /**
     * @var GrantTypeInterface[]
     */
    protected $enabledGrantTypes = [];

    /**
     * @var DateInterval[]
     */
    protected $grantTypeAccessTokenTTL = [];

    /**
     * @var CryptKey
     */
    protected $privateKey;

    /**
     * @var CryptKey
     */
    protected $publicKey;

    /**
     * @var ResponseTypeInterface
     */
    protected $responseType;

    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var ScopeRepositoryInterface
     */
    private $scopeRepository;

    /**
     * @var string|Key
     */
    private $encryptionKey;

    /**
     * @var string
     */
    private $defaultScope = '';

    /**
     * @var bool
     */
    private $revokeRefreshTokens = true;

    /**
     * New server instance.
     *
     * @param ClientRepositoryInterface      $clientRepository
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param ScopeRepositoryInterface       $scopeRepository
     * @param CryptKey|string                $privateKey
     * @param string|Key                     $encryptionKey
     * @param null|ResponseTypeInterface     $responseType
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $privateKey,
        $encryptionKey,
        ResponseTypeInterface $responseType = null
    ) {
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;

        if ($privateKey instanceof CryptKey === false) {
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
     * Enable a grant type on the server.
     *
     * @param GrantTypeInterface $grantType
     * @param null|DateInterval  $accessTokenTTL
     */
    public function enableGrantType(GrantTypeInterface $grantType, DateInterval $accessTokenTTL = null)
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
     * @param ServerRequestInterface $request
     *
     * @throws OAuthServerException
     *
     * @return AuthorizationRequest
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request)
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
     *
     * @param AuthorizationRequest $authRequest
     * @param ResponseInterface    $response
     *
     * @return ResponseInterface
     */
    public function completeAuthorizationRequest(AuthorizationRequest $authRequest, ResponseInterface $response)
    {
        return $this->enabledGrantTypes[$authRequest->getGrantTypeId()]
            ->completeAuthorizationRequest($authRequest)
            ->generateHttpResponse($response);
    }

    /**
     * Return an access token response.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     *
     * @throws OAuthServerException
     *
     * @return ResponseInterface
     */
    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseInterface $response)
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

            if ($tokenResponse instanceof ResponseTypeInterface) {
                return $tokenResponse->generateHttpResponse($response);
            }
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Get the token type that grants will return in the HTTP response.
     *
     * @return ResponseTypeInterface
     */
    protected function getResponseType()
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
     *
     * @param string $defaultScope
     */
    public function setDefaultScope($defaultScope)
    {
        $this->defaultScope = $defaultScope;
    }

    /**
     * Sets whether to revoke refresh tokens or not (for all grant types).
     *
     * @param bool $revokeRefreshTokens
     */
    public function revokeRefreshTokens(bool $revokeRefreshTokens): void
    {
        $this->revokeRefreshTokens = $revokeRefreshTokens;
    }
}
