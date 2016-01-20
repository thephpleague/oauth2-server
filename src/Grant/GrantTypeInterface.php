<?php
/**
 * OAuth 2.0 Grant type interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\Event\EmitterInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Grant type interface
 */
interface GrantTypeInterface
{
    /**
     * Return the identifier
     *
     * @return string
     */
    public function getIdentifier();

    /**
     * Details what the grant responds with
     *
     * @return string
     */
    public function respondsWith();

    /**
     * Respond to an incoming request
     *
     * @param \Psr\Http\Message\ServerRequestInterface                  $request
     * @param \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface $responseType
     * @param \DateInterval                                             $accessTokenTTL
     * @param \DateInterval                                             $refreshTokenTTL
     *
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL,
        \DateInterval $refreshTokenTTL
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
     * @return boolean
     */
    public function canRespondToRequest(ServerRequestInterface $request);

    /**
     * Set the event emitter
     *
     * @param \League\Event\EmitterInterface $emitter
     */
    public function setEmitter(EmitterInterface $emitter);

    /**
     * Set the client repository
     *
     * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface $clientRepository
     */
    public function setClientRepository(ClientRepositoryInterface $clientRepository);

    /**
     * Set the access token repository
     *
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository);

    /**
     * Set the scope repository
     *
     * @param \League\OAuth2\Server\Repositories\ScopeRepositoryInterface $scopeRepository
     */
    public function setScopeRepository(ScopeRepositoryInterface $scopeRepository);

    /**
     * Set the path to the private key
     *
     * @param string $pathToPrivateKey
     */
    public function setPathToPrivateKey($pathToPrivateKey);

    /**
     * Set the path to the public key
     *
     * @param string $pathToPublicKey
     */
    public function setPathToPublicKey($pathToPublicKey);
}
