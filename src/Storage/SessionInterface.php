<?php
/**
 * OAuth 2.0 Session storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

/**
 * Session storage interface
 */
interface SessionInterface
{
    /**
     * Get a session from it's identifier
     * @param string $sessionId
     * @return \League\OAuth2\Server\Entity\Session
     */
    public function get($sessionId);

    /**
     * Get a session from an access token
     * @param  \League\OAuth2\Server\Entity\AccessToken $accessToken The access token
     * @return \League\OAuth2\Server\Entity\Session
     */
    public function getByAccessToken($accessToken);

    /**
     * Get a session from an auth code
     * @param  \League\OAuth2\Server\Entity\AuthCode $authCode The auth code
     * @return \League\OAuth2\Server\Entity\Session
     */
    public function getByAuthCode($authCode);

    /**
     * Get a session's scopes
     * @param  integer $sessionId
     * @return array Array of \League\OAuth2\Server\Entity\Scope
     */
    public function getScopes($sessionId);

    /**
     * Create a new session
     * @param  string $ownerType         Session owner's type (user, client)
     * @param  string $ownerId           Session owner's ID
     * @param  string $clientId          Client ID
     * @param  string $clientRedirectUri Client redirect URI (default = null)
     * @return integer The session's ID
     */
    public function create($ownerType, $ownerId, $clientId, $clientRedirectUri = null);

    /**
     * Associate a scope with a session
     * @param  integer $sessionId
     * @param  string  $scopeId    The scopes ID might be an integer or string
     * @return void
     */
    public function associateScope($sessionId, $scopeId);
}
