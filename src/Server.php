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
     * @var DateInterval[]
     */
    protected $grantTypeTokensTTL = [];

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
     * New server instance
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
     * Enable a grant type on the server
     *
     * @param \League\OAuth2\Server\Grant\GrantTypeInterface $grantType
     * @param DateInterval|null                              $accessTokenTTL
     * @param DateInterval|null                              $refreshTokenTTL
     */
    public function enableGrantType(
        GrantTypeInterface $grantType,
        \DateInterval $accessTokenTTL,
        \DateInterval $refreshTokenTTL = null
    ) {
        $grantType->setAccessTokenRepository($this->accessTokenRepository);
        $grantType->setClientRepository($this->clientRepository);
        $grantType->setScopeRepository($this->scopeRepository);
        $grantType->setPathToPrivateKey($this->privateKeyPath);
        $grantType->setPathToPublicKey($this->publicKeyPath);
        $grantType->setEmitter($this->getEmitter());

        $this->enabledGrantTypes[$grantType->getIdentifier()] = $grantType;

        $this->grantTypeTokensTTL[$grantType->getIdentifier()] = [
            'access'  => $accessTokenTTL,
            'refresh' => $refreshTokenTTL !== null ? $refreshTokenTTL : new \DateInterval('P1M'),
        ];
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
                    $this->getResponseType(),
                    $this->grantTypeTokensTTL[$grantType->getIdentifier()]['access'],
                    $this->grantTypeTokensTTL[$grantType->getIdentifier()]['refresh']
                );
            }
        }

        if (!$tokenResponse instanceof ResponseTypeInterface) {
            return OAuthServerException::unsupportedGrantType()->generateHttpResponse($response);
        }

        return $tokenResponse->generateHttpResponse($response);
    }

    /**
     * Get the token type that grants will return in the HTTP response
     *
     * @return ResponseTypeInterface
     */
    public function getResponseType()
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
