<?php

namespace League\OAuth2\Server;

use DateInterval;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;

class Server implements EmitterAwareInterface
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
     * @var string
     */
    protected $privateKeyPath;

    /**
     * @var ResponseTypeInterface
     */
    protected $responseType;

    /**
     * @var string
     */
    private $publicKeyPath;

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
     * @param string                                                            $privateKeyPath
     * @param string                                                            $publicKeyPath
     * @param null|\League\OAuth2\Server\ResponseTypes\ResponseTypeInterface    $responseType
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $privateKeyPath,
        $publicKeyPath,
        ResponseTypeInterface $responseType = null
    ) {
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;
        $this->privateKeyPath = $privateKeyPath;
        $this->publicKeyPath = $publicKeyPath;
        $this->responseType = $responseType;
    }

    /**
     * Enable a grant type on the server.
     *
     * @param \League\OAuth2\Server\Grant\GrantTypeInterface $grantType
     * @param \DateInterval                                  $accessTokenTTL
     */
    public function enableGrantType(GrantTypeInterface $grantType, DateInterval $accessTokenTTL)
    {
        $grantType->setAccessTokenRepository($this->accessTokenRepository);
        $grantType->setClientRepository($this->clientRepository);
        $grantType->setScopeRepository($this->scopeRepository);
        $grantType->setPathToPrivateKey($this->privateKeyPath);
        $grantType->setPathToPublicKey($this->publicKeyPath);
        $grantType->setEmitter($this->getEmitter());

        $this->enabledGrantTypes[$grantType->getIdentifier()] = $grantType;

        $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()] = $accessTokenTTL;
    }

    /**
     * Return an access token response.
     *
     * @param \Psr\Http\Message\ServerRequestInterface|null $request
     * @param \Psr\Http\Message\ResponseInterface|null      $response
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function respondToRequest(ServerRequestInterface $request = null, ResponseInterface $response = null)
    {
        if (!$request instanceof ServerRequestInterface) {
            $request = ServerRequestFactory::fromGlobals();
        }

        if (!$response instanceof ResponseInterface) {
            $response = new Response();
        }

        $tokenResponse = null;
        while ($tokenResponse === null && $grantType = array_shift($this->enabledGrantTypes)) {
            /** @var \League\OAuth2\Server\Grant\GrantTypeInterface $grantType */
            if ($grantType->canRespondToRequest($request)) {
                $tokenResponse = $grantType->respondToRequest(
                    $request,
                    $this->getResponseType(),
                    $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()]
                );
            }
        }

        if ($tokenResponse instanceof ResponseInterface) {
            return $tokenResponse;
        }

        if ($tokenResponse instanceof ResponseTypeInterface) {
            return $tokenResponse->generateHttpResponse($response);
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Determine the access token validity.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \Psr\Http\Message\ServerRequestInterface
     */
    public function validateAuthenticatedRequest(ServerRequestInterface $request)
    {
        return $this->getResponseType()->validateAccessToken($request);
    }

    /**
     * Get the token type that grants will return in the HTTP response.
     *
     * @return ResponseTypeInterface
     */
    protected function getResponseType()
    {
        if (!$this->responseType instanceof ResponseTypeInterface) {
            $this->responseType = new BearerTokenResponse(
                $this->privateKeyPath,
                $this->publicKeyPath,
                $this->accessTokenRepository
            );
        }

        return $this->responseType;
    }
}
