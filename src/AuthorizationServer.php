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
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationServer implements EmitterAwareInterface
{
    use EmitterAwareTrait;

    /**
     * @var \League\OAuth2\Server\Grant\GrantTypeInterface[]
     */
    protected $enabledGrantTypes = [];

    /**
     * @var \DateInterval[]
     */
    protected $grantTypeAccessTokenTTL = [];

    /**
     * @var \League\OAuth2\Server\CryptKey
     */
    protected $privateKey;

    /**
     * @var \League\OAuth2\Server\CryptKey
     */
    protected $publicKey;

    /**
     * @var ResponseTypeInterface
     */
    protected $responseType;

    /**
     * @var \League\OAuth2\Server\Repositories\ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\ScopeRepositoryInterface
     */
    private $scopeRepository;

    /**
     * New server instance.
     *
     * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface      $clientRepository
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface $accessTokenRepository
     * @param \League\OAuth2\Server\Repositories\ScopeRepositoryInterface       $scopeRepository
     * @param \League\OAuth2\Server\CryptKey|string                             $privateKey
     * @param \League\OAuth2\Server\CryptKey|string                             $publicKey
     * @param null|\League\OAuth2\Server\ResponseTypes\ResponseTypeInterface    $responseType
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $privateKey,
        $publicKey,
        ResponseTypeInterface $responseType = null
    ) {
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;

        if (!$privateKey instanceof CryptKey) {
            $privateKey = new CryptKey($privateKey);
        }
        $this->privateKey = $privateKey;

        if (!$publicKey instanceof CryptKey) {
            $publicKey = new CryptKey($publicKey);
        }
        $this->publicKey = $publicKey;

        $this->responseType = $responseType;
    }

    /**
     * Enable a grant type on the server.
     *
     * @param \League\OAuth2\Server\Grant\GrantTypeInterface $grantType
     * @param \DateInterval                                  $accessTokenTTL
     */
    public function enableGrantType(GrantTypeInterface $grantType, DateInterval $accessTokenTTL = null)
    {
        if ($accessTokenTTL instanceof DateInterval === false) {
            $accessTokenTTL = new \DateInterval('PT1H');
        }

        $grantType->setAccessTokenRepository($this->accessTokenRepository);
        $grantType->setClientRepository($this->clientRepository);
        $grantType->setScopeRepository($this->scopeRepository);
        $grantType->setPrivateKey($this->privateKey);
        $grantType->setPublicKey($this->publicKey);
        $grantType->setEmitter($this->getEmitter());

        $this->enabledGrantTypes[$grantType->getIdentifier()] = $grantType;
        $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()] = $accessTokenTTL;
    }

    /**
     * Validate an authorization request
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \League\OAuth2\Server\RequestTypes\AuthorizationRequest|null
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request)
    {
        $authRequest = null;
        $enabledGrantTypes = $this->enabledGrantTypes;
        while ($authRequest === null && $grantType = array_shift($enabledGrantTypes)) {
            /** @var \League\OAuth2\Server\Grant\GrantTypeInterface $grantType */
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                $authRequest = $grantType->validateAuthorizationRequest($request);

                return $authRequest;
            }
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Complete an authorization request
     *
     * @param \League\OAuth2\Server\RequestTypes\AuthorizationRequest $authRequest
     * @param \Psr\Http\Message\ResponseInterface                     $response
     *
     * @return \Psr\Http\Message\ResponseInterface
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
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseInterface $response)
    {
        $tokenResponse = null;
        while ($tokenResponse === null && $grantType = array_shift($this->enabledGrantTypes)) {
            /** @var \League\OAuth2\Server\Grant\GrantTypeInterface $grantType */
            if ($grantType->canRespondToAccessTokenRequest($request)) {
                $tokenResponse = $grantType->respondToAccessTokenRequest(
                    $request,
                    $this->getResponseType(),
                    $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()]
                );
            }
        }

        if ($tokenResponse instanceof ResponseTypeInterface) {
            return $tokenResponse->generateHttpResponse($response);
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
        if (!$this->responseType instanceof ResponseTypeInterface) {
            $this->responseType = new BearerTokenResponse();
        }

        $this->responseType->setPrivateKey($this->privateKey);

        return $this->responseType;
    }
}
