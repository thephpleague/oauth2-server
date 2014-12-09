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

use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;

/**
 * Access token interface
 */
interface AccessTokenInterface extends StorageInterface
{
    /**
     * Get an instance of Entity\AccessTokenInterface
     * @param  string $token The access token
     * @return \League\OAuth2\Server\Entity\AccessTokenInterface
     */
    public function get($token);

    /**
     * Get the scopes for an access token
     * @param \League\OAuth2\Server\Entity\AccessTokenInterface $token The access token
     * @return array Array of \League\OAuth2\Server\Entity\ScopeInterface
     */
    public function getScopes(AccessTokenEntityInterface $token);

    /**
     * Creates a new access token
     *
     * @param string         $token      The access token
     * @param integer        $expireTime The expire time expressed as a unix timestamp
     * @param string|integer $sessionId  The session ID
     *
     * @return void
     */
    public function create($token, $expireTime, $sessionId);

    /**
     * Associate a scope with an access token
     * @param  \League\OAuth2\Server\Entity\AccessTokenInterface $token The access token
     * @param  \League\OAuth2\Server\Entity\ScopeInterface       $scope The scope
     * @return void
     */
    public function associateScope(AccessTokenEntityInterface $token, ScopeEntityInterface $scope);

    /**
     * Delete an access token
     * @param  \League\OAuth2\Server\Entity\AccessTokenInterface $token The access token to delete
     * @return void
     */
    public function delete(AccessTokenEntityInterface $token);
}
