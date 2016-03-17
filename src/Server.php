<?php

namespace League\OAuth2\Server;

use DateInterval;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

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
     * @var \League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface
     */
    private $authorizationValidator;

    /**
     * New server instance.
     *
     * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface                       $clientRepository
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface                  $accessTokenRepository
     * @param \League\OAuth2\Server\Repositories\ScopeRepositoryInterface                        $scopeRepository
     * @param string                                                                             $privateKeyPath
     * @param string                                                                             $publicKeyPath
     * @param null|\League\OAuth2\Server\ResponseTypes\ResponseTypeInterface                     $responseType
     * @param null|\League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface $authorizationValidator
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $privateKeyPath,
        $publicKeyPath,
        ResponseTypeInterface $responseType = null,
        AuthorizationValidatorInterface $authorizationValidator = null
    ) {
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;
        $this->privateKeyPath = $privateKeyPath;
        $this->publicKeyPath = $publicKeyPath;
        $this->responseType = $responseType;
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
        $grantType->setPrivateKeyPath($this->privateKeyPath);
        $grantType->setPublicKeyPath($this->publicKeyPath);
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
        return $this->getAuthorizationValidator()->validateAuthorization($request);
    }

    /**
     * Get the token type that grants will return in the HTTP response.
     *
     * @return ResponseTypeInterface
     */
    protected function getResponseType()
    {
        if (!$this->responseType instanceof ResponseTypeInterface) {
            $this->responseType = new BearerTokenResponse($this->accessTokenRepository);
        }

        $this->responseType->setPublicKeyPath($this->publicKeyPath);
        $this->responseType->setPrivateKeyPath($this->privateKeyPath);

        return $this->responseType;
    }

    /**
     * @return \League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface
     */
    protected function getAuthorizationValidator()
    {
        if (!$this->authorizationValidator instanceof AuthorizationValidatorInterface) {
            $this->authorizationValidator = new BearerTokenValidator($this->accessTokenRepository);
        }

        $this->authorizationValidator->setPublicKeyPath($this->publicKeyPath);
        $this->authorizationValidator->setPrivateKeyPath($this->privateKeyPath);

        return $this->authorizationValidator;
    }
}
