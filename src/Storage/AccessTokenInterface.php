<?php
/**
 * OAuth 2.0 Access token storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

use League\OAuth2\Server\Entity\AccessToken;
use League\OAuth2\Server\Entity\AbstractToken;
use League\OAuth2\Server\Entity\RefreshToken;
use League\OAuth2\Server\Entity\AuthCode;
use League\OAuth2\Server\Entity\Scope;

/**
 * Access token interface
 */
interface AccessTokenInterface
{
    /**
     * Get an instance of Entity\AccessToken
     * @param  string $token The access token
     * @return \League\OAuth2\Server\Entity\AccessToken
     */
    public function get($token);

    /**
     * Get the access token associated with an access token
     * @param \League\OAuth2\Server\Entity\RefreshToken $refreshToken
     * @return \League\OAuth2\Server\Entity\AccessToken
     */
    public function getByRefreshToken(RefreshToken $refreshToken);

    /**
     * Get the scopes for an access token
     * @param  \League\OAuth2\Server\Entity\AbstractToken $token The access token
     * @return array Array of \League\OAuth2\Server\Entity\Scope
     */
    public function getScopes(AbstractToken $token);

    /**
     * Creates a new access token
     * @param  string $token The access token
     * @param  integer $expireTime The expire time expressed as a unix timestamp
     * @param  string|integer $sessionId The session ID
     * @return \League\OAuth2\Server\Entity\AccessToken
     */
    public function create($token, $expireTime, $sessionId);

    /**
     * Associate a scope with an acess token
     * @param  \League\OAuth2\Server\Entity\AbstractToken $token The access token
     * @param  \League\OAuth2\Server\Entity\Scope $scope The scope
     * @return void
     */
    public function associateScope(AbstractToken $token, Scope $scope);

    /**
     * Delete an access token
     * @param  \League\OAuth2\Server\Entity\AbstractToken $token The access token to delete
     * @return void
     */
    public function delete(AbstractToken $token);
}
