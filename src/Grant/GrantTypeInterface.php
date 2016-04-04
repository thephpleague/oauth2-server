<?php
/**
 * OAuth 2.0 Grant type interface.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Grant;

use League\Event\EmitterAwareInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Grant type interface.
 */
interface GrantTypeInterface extends EmitterAwareInterface
{
    /**
     * Set refresh token TTL.
     *
     * @param \DateInterval $refreshTokenTTL
     */
    public function setRefreshTokenTTL(\DateInterval $refreshTokenTTL);

    /**
     * Return the grant identifier that can be used in matching up requests.
     *
     * @return string
     */
    public function getIdentifier();

    /**
     * Respond to an incoming request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface                     $request
     * @param \League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface $responseFactory
     * @param \DateInterval                                                $accessTokenTTL
     *
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseFactoryInterface $responseFactory,
        \DateInterval $accessTokenTTL
    );

    /**
     * The grant type should return true if it is able to respond to this request.
     *
     * For example most grant types will check that the $_POST['grant_type'] property matches it's identifier property.
     *
     * Some grants, such as the authorization code grant can respond to multiple requests
     *  - i.e. a client requesting an authorization code and requesting an access token
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    public function canRespondToRequest(ServerRequestInterface $request);

    /**
     * Set the client repository.
     *
     * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface $clientRepository
     */
    public function setClientRepository(ClientRepositoryInterface $clientRepository);

    /**
     * Set the access token repository.
     *
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository);

    /**
     * Set the scope repository.
     *
     * @param \League\OAuth2\Server\Repositories\ScopeRepositoryInterface $scopeRepository
     */
    public function setScopeRepository(ScopeRepositoryInterface $scopeRepository);
}
