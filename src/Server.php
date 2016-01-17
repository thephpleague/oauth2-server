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
    private $defaultPublicKeyPath;

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
     * New server instance
     *
     * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface      $clientRepository
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface $accessTokenRepository
     * @param \League\OAuth2\Server\Repositories\ScopeRepositoryInterface       $scopeRepository
     * @param string                                                            $defaultPrivateKeyPath
     * @param string                                                            $defaultPublicKeyPath
     * @param null|\League\OAuth2\Server\ResponseTypes\ResponseTypeInterface    $responseType
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $defaultPrivateKeyPath,
        $defaultPublicKeyPath,
        ResponseTypeInterface $responseType = null
    ) {
        $this->defaultPrivateKeyPath = $defaultPrivateKeyPath;
        $this->defaultPublicKeyPath = $defaultPublicKeyPath;
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;
        $this->defaultResponseType = $responseType;
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
     * Enable a grant type on the server
     *
     * @param \League\OAuth2\Server\Grant\GrantTypeInterface $grantType
     * @param DateInterval                                   $accessTokenTTL
     */
    public function enableGrantType(
        GrantTypeInterface $grantType,
        \DateInterval $accessTokenTTL
    ) {
        $grantType->setAccessTokenRepository($this->accessTokenRepository);
        $grantType->setClientRepository($this->clientRepository);
        $grantType->setScopeRepository($this->scopeRepository);

        $grantType->setEmitter($this->getEmitter());
        $this->enabledGrantTypes[$grantType->getIdentifier()] = $grantType;

        // Set grant response type
        $this->grantResponseTypes[$grantType->getIdentifier()] = $this->getDefaultResponseType();

        // Set grant access token TTL
        $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()] = $accessTokenTTL;
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
