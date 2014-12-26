<?php
/**
 * OAuth 2.0 Auth code storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

use League\OAuth2\Server\Entity\AuthCodeInterface as AuthCodeEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;

/**
 * Auth code storage interface
 */
interface AuthCodeInterface extends StorageInterface
{
    /**
     * Get the auth code
     * @param  string                  $code
     * @return AuthCodeEntityInterface
     */
    public function get($code);

    /**
     * Create an auth code.
     *
     * @param string  $token       The token ID
     * @param integer $expireTime  Token expire time
     * @param integer $sessionId   Session identifier
     * @param string  $redirectUri Client redirect uri
     *
     * @return void
     */
    public function create($token, $expireTime, $sessionId, $redirectUri);

    /**
     * Get the scopes for an access token
     * @param  AuthCodeEntityInterface $token The auth code
     * @return array                   Array of \League\OAuth2\Server\Entity\ScopeInterface
     */
    public function getScopes(AuthCodeEntityInterface $token);

    /**
     * Associate a scope with an access token
     * @param  \League\OAuth2\Server\Entity\AuthCodeInterface $token The auth code
     * @param  ScopeEntityInterface                           $scope The scope
     * @return void
     */
    public function associateScope(AuthCodeEntityInterface $token, ScopeEntityInterface $scope);

    /**
     * Delete an access token
     * @param  AuthCodeEntityInterface $token The access token to delete
     * @return void
     */
    public function delete(AuthCodeEntityInterface $token);
}
