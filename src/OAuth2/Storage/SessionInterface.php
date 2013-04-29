<?php
/**
 * OAuth 2.0 Session storage interface
 *
 * @package     lncd/oauth2
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 University of Lincoln
 * @license     http://mit-license.org/
 * @link        http://github.com/lncd/oauth2
 */

namespace OAuth2\Storage;

interface SessionInterface
{
    /**
     * Create a new session
     * @param  string $clientId  The client ID
     * @param  string $ownerType The type of the session owner (e.g. "user")
     * @param  string $ownerId   The ID of the session owner (e.g. "123")
     * @return int               The session ID
     */
	public function createSession(string $clientId, string $ownerType, string $ownerId);

    /**
     * Delete a session
     * @param  string $clientId  The client ID
     * @param  string $ownerType The type of the session owner (e.g. "user")
     * @param  string $ownerId   The ID of the session owner (e.g. "123")
     * @return void
     */
    public function deleteSession(string $clientId, string $ownerType, string $ownerId);

    /**
     * Associate a redirect URI with a session
     * @param  int    $sessionId   The session ID
     * @param  string $redirectUri The redirect URI
     * @return void
     */
    public function associateRedirectUri(int $sessionId, string $redirectUri);

    /**
     * Remove an associated redirect URI
     * @param  int    $sessionId The session ID
     * @return void
     */
    public function removeRedirectUri(int $sessionId);

    /**
     * Associate an access token with a session
     * @param  int    $sessionId   The session ID
     * @param  string $accessToken The access token
     * @param  int    $expireTime  Unix timestamp of the access token expiry time
     * @return void
     */
    public function associateAccessToken(int $sessionId, string $accessToken, int $expireTime);

    /**
     * Remove an associated access token from a session
     * @param  int    $sessionId   The session ID
     * @return void
     */
    public function removeAccessToken(int $sessionId);

    /**
     * Associate a refresh token with a session
     * @param  int    $sessionId    The session ID
     * @param  string $refreshToken The refresh token
     * @return void
     */
    public function associateRefreshToken(int $sessionId, string $refreshToken);

    /**
     * Remove an associated refresh token from a session
     * @param  int    $sessionId   The session ID
     * @return void
     */
    public function removeRefreshToken(int $sessionId);

    /**
     * Assocate an authorization code with a session
     * @param  int    $sessionId  The session ID
     * @param  string $authCode   The authorization code
     * @param  int    $expireTime Unix timestamp of the access token expiry time
     * @param  string $scopeIds   Comma seperated list of scope IDs to be later associated (default = null)
     * @return void
     */
    public function associateAuthCode(int $sessionId, string $authCode, int $expireTime, string $scopeIds = null);

    /**
     * Remove an associated authorization token from a session
     * @param  int    $sessionId   The session ID
     * @return void
     */
    public function removeAuthCode(int $sessionId);

    /**
     * Validate an authorization code
     * @param  string $clientId    The client ID
     * @param  string $redirectUri The redirect URI
     * @param  string $authCode    The authorization code
     * @return void
     */
    public function validateAuthCode(string $clientId, string $redirectUri, string $authCode);

    /**
     * Validate an access token
     * @param  string $accessToken [description]
     * @return void
     */
    public function validateAccessToken(string $accessToken);

    /**
     * Validate a refresh token
     * @param  string $accessToken The access token
     * @return void
     */
    public function validateRefreshToken(string $accessToken);

    /**
     * Associate a scope with an access token
     * @param  int    $accessTokenId The ID of the access token
     * @param  int    $scopeId       The ID of the scope
     * @return void
     */
    public function associateScope(int $accessTokenId, int $scopeId);

    /**
     * Get all associated access tokens for an access token
     * @param  string $accessToken The access token
     * @return array
     */
    public function getScopes(string $accessToken);
}
