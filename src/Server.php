<?php

namespace League\OAuth2\Server;

use DateInterval;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
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
     * @var ResponseTypeInterface[]
     */
    protected $grantResponseTypes = [];

    /**
     * @var DateInterval[]
     */
    protected $grantTypeAccessTokenTTL = [];

    /**
     * @var string
     */
    protected $defaultPrivateKeyPath;

    /**
     * @var ResponseTypeInterface
     */
    protected $defaultResponseType;

    /**
     * @var string
     */

    /**
     * New server instance
     *
     * @param string       $defaultPrivateKeyPath
     * @param DateInterval $defaultAccessTokenTTL
     */
    public function __construct($defaultPrivateKeyPath, \DateInterval $defaultAccessTokenTTL = null)
    {
        $this->defaultPrivateKeyPath = $defaultPrivateKeyPath;
        $this->defaultAccessTokenTTL = $defaultAccessTokenTTL;
    }

    /**
     * Set the default token type that grants will return
     *
     * @param ResponseTypeInterface $defaultTokenType
     */
    public function setDefaultResponseType(ResponseTypeInterface $defaultTokenType)
    {
        $this->defaultResponseType = $defaultTokenType;
    }

    /**
     * Get the default token type that grants will return
     *
     * @return ResponseTypeInterface
     */
    protected function getDefaultResponseType()
    {
        if (!$this->defaultResponseType instanceof ResponseTypeInterface) {
            $this->defaultResponseType = new BearerTokenResponse(
                $this->defaultPrivateKeyPath,
                $this->defaultPublicKeyPath,
                $this->accessTokenRepository
            );
        }

        return $this->defaultResponseType;
    }

    /**
    /**
     * Enable a grant type on the server
     *
     * @param \League\OAuth2\Server\Grant\GrantTypeInterface $grantType
     * @param ResponseTypeInterface                          $responseType
     * @param DateInterval                                   $accessTokenTTL
     */
    public function enableGrantType(
        GrantTypeInterface $grantType,
        ResponseTypeInterface $responseType = null,
        \DateInterval $accessTokenTTL
    ) {
        $grantType->setAccessTokenRepository($this->accessTokenRepository);
        $grantType->setClientRepository($this->clientRepository);
        $grantType->setScopeRepository($this->scopeRepository);

        $grantType->setEmitter($this->getEmitter());
        $this->enabledGrantTypes[$grantType->getIdentifier()] = $grantType;

        // Set grant response type
        if ($responseType instanceof ResponseTypeInterface) {
            $this->grantResponseTypes[$grantType->getIdentifier()] = $responseType;
        } else {
            $this->grantResponseTypes[$grantType->getIdentifier()] = $this->getDefaultResponseType();
        }

        // Set grant access token TTL
        if ($accessTokenTTL instanceof \DateInterval) {
            $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()] = $accessTokenTTL;
        } else {
            $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()] = $this->getDefaultAccessTokenTTL();
        }
    }

    /**
     * Return an access token response
     *
     * @param \Psr\Http\Message\ServerRequestInterface|null $request
     * @param \Psr\Http\Message\ResponseInterface|null      $response
     *
     * @return \Psr\Http\Message\ResponseInterface
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
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
        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToRequest($request)) {
                $tokenResponse = $grantType->respondToRequest(
                    $request,
                    $this->grantResponseTypes[$grantType->getIdentifier()],
                    $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()]
                );
            }
        }

        if (!$tokenResponse instanceof ResponseTypeInterface) {
            return OAuthServerException::unsupportedGrantType()->generateHttpResponse($response);
        }

        return $tokenResponse->generateHttpResponse($response);
    }

    /**
     * PSR7 middleware callable
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     * @param callable                                 $next
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $next)
    {
        $response = $this->respondToRequest($request, $response);

        if (in_array($response->getStatusCode(), [400, 401, 500])) {
            return $response;
        }

        return $next($request, $response);
    }
}
