<?php

namespace League\OAuth2\Server;

use DateInterval;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\Grant\GrantTypeInterface;
//use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
//use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
//use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RepositoryInterface;
//use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
//use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\TokenTypes\BearerTokenType;
use League\OAuth2\Server\TokenTypes\TokenTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\ServerRequestFactory;

class Server implements EmitterAwareInterface
{
    use EmitterAwareTrait;

    /**
     * @var \League\OAuth2\Server\Grant\GrantTypeInterface[]
     */
    protected $enabledGrantTypes = [];

    /**
     * @var TokenTypeInterface[]
     */
    protected $grantTypeTokenTypes = [];

    /**
     * @var DateInterval[]
     */
    protected $grantTypeAccessTokenTTL = [];

    /**
     * @var TokenTypeInterface
     */
    protected $defaultTokenType;

    /**
     * @var DateInterval
     */
    protected $defaultAccessTokenTTL;

    /**
     * @var string
     */
    protected $scopeDelimiterString = ' ';

    /**
     * @var RepositoryInterface[]
     */
//    protected $repositories = [];

    /**
     * New server instance
     */
    public function __construct()
    {
        $this->setDefaultTokenType(new BearerTokenType());
        $this->setDefaultAccessTokenTTL(new DateInterval('PT01H')); // default of 1 hour
    }

    /**
     * Set the default token type that grants will return
     *
     * @param TokenTypeInterface $defaultTokenType
     */
    public function setDefaultTokenType(TokenTypeInterface $defaultTokenType)
    {
        $this->defaultTokenType = $defaultTokenType;
    }

    /**
     * Set the delimiter string used to separate scopes in a request
     *
     * @param string $scopeDelimiterString
     */
    public function setScopeDelimiterString($scopeDelimiterString)
    {
        $this->scopeDelimiterString = $scopeDelimiterString;
    }

    /**
     * Set the default TTL of access tokens
     *
     * @param DateInterval $defaultAccessTokenTTL
     */
    public function setDefaultAccessTokenTTL(DateInterval $defaultAccessTokenTTL)
    {
        $this->defaultAccessTokenTTL = $defaultAccessTokenTTL;
    }

    /**
     * Enable a grant type on the server
     *
     * @param \League\OAuth2\Server\Grant\GrantTypeInterface $grantType
     * @param TokenTypeInterface                             $tokenType
     * @param DateInterval                                   $accessTokenTTL
     */
    public function enableGrantType(
        GrantTypeInterface $grantType,
        TokenTypeInterface $tokenType = null,
        DateInterval $accessTokenTTL = null
    ) {
        $grantType->setEmitter($this->getEmitter());
        $this->enabledGrantTypes[$grantType->getIdentifier()] = $grantType;

        // Set grant response type
        if ($tokenType instanceof TokenTypeInterface) {
            $this->grantTypeTokenTypes[$grantType->getIdentifier()] = $tokenType;
        } else {
            $this->grantTypeTokenTypes[$grantType->getIdentifier()] = $this->defaultTokenType;
        }

        // Set grant access token TTL
        if ($accessTokenTTL instanceof DateInterval) {
            $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()] = $accessTokenTTL;
        } else {
            $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()] = $this->defaultAccessTokenTTL;
        }
    }

    /**
     * Return an access token response
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \League\OAuth2\Server\TokenTypes\TokenTypeInterface
     * @throws \League\OAuth2\Server\Exception\InvalidGrantException
     */
    public function respondToRequest(ServerRequestInterface $request = null)
    {
        if ($request === null) {
            $request = ServerRequestFactory::fromGlobals();
        }

        $response = null;
        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToRequest($request)) {
                $response = $grantType->respondToRequest(
                    $request,
                    $this->grantTypeTokenTypes[$grantType->getIdentifier()],
                    $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()],
                    $this->scopeDelimiterString
                );
            }
        }

        if ($response === null) {
            // do something here
        }

        return $response;
    }

    /**
     * @param \League\OAuth2\Server\Repositories\RepositoryInterface $repository
     */
    /*public function addRepository(RepositoryInterface $repository)
    {
        switch ($repository) {
            case ($repository instanceof AccessTokenRepositoryInterface):
                $this->repositories[AccessTokenRepositoryInterface::class] = $repository;
                break;
            case ($repository instanceof ClientRepositoryInterface):
                $this->repositories[ClientRepositoryInterface::class] = $repository;
                break;
            case ($repository instanceof ScopeRepositoryInterface):
                $this->repositories[ScopeRepositoryInterface::class] = $repository;
                break;
            case ($repository instanceof UserRepositoryInterface):
                $this->repositories[UserRepositoryInterface::class] = $repository;
                break;
            case ($repository instanceof AuthCodeRepositoryInterface):
                $this->repositories[AuthCodeRepositoryInterface::class] = $repository;
                break;
        }
    }*/
}
