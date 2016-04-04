<?php

namespace League\OAuth2\Server;

use DateInterval;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class Server implements EmitterAwareInterface
{
    use EmitterAwareTrait;

    /**
     * @var GrantTypeInterface[]
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
     * @var ResponseFactoryInterface
     */
    protected $responseFactory;

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
     * @var AuthorizationValidatorInterface
     */
    private $authorizationValidator;

    /**
     * New server instance.
     *
     * @param ClientRepositoryInterface       $clientRepository
     * @param AccessTokenRepositoryInterface  $accessTokenRepository
     * @param ScopeRepositoryInterface        $scopeRepository
     * @param ResponseFactoryInterface        $responseFactory
     * @param AuthorizationValidatorInterface $authorizationValidator
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        ResponseFactoryInterface $responseFactory,
        AuthorizationValidatorInterface $authorizationValidator
    ) {
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;
        $this->responseFactory = $responseFactory;
        $this->authorizationValidator = $authorizationValidator;
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
    public function respondToRequest(ServerRequestInterface $request, ResponseInterface $response)
    {
        $tokenResponse = null;
        while ($tokenResponse === null && $grantType = array_shift($this->enabledGrantTypes)) {
            /** @var \League\OAuth2\Server\Grant\GrantTypeInterface $grantType */
            if ($grantType->canRespondToRequest($request)) {
                $tokenResponse = $grantType->respondToRequest(
                    $request,
                    $this->responseFactory,
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
        return $this->authorizationValidator->validateAuthorization($request);
    }
}
