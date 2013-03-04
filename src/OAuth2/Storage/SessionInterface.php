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
     * Create a new OAuth session
     *
     * Example SQL query:
     *
     * <code>
     * INSERT INTO oauth_sessions (client_id, redirect_uri, owner_type,
     * owner_id, auth_code, access_token, refresh_token, stage, first_requested,
     * last_updated) VALUES ($clientId, $redirectUri, $type, $typeId, $authCode,
     * $accessToken, $stage, UNIX_TIMESTAMP(NOW()), UNIX_TIMESTAMP(NOW()))
     * </code>
     *
     * @param  string $clientId          The client ID
     * @param  string $redirectUri       The redirect URI
     * @param  string $type              The session owner's type (default = "user")
     * @param  string $typeId            The session owner's ID (default = "null")
     * @param  string $authCode          The authorisation code (default = "null")
     * @param  string $accessToken       The access token (default = "null")
     * @param  string $refreshToken      The refresh token (default = "null")
     * @param  int    $accessTokenExpire The expiry time of an access token as a unix timestamp
     * @param  string $stage             The stage of the session (default ="request")
     * @return int                       The session ID
     */
    public function createSession(
        $clientId,
        $redirectUri,
        $type = 'user',
        $typeId = null,
        $authCode = null,
        $accessToken = null,
        $refreshToken = null,
        $accessTokenExpire = null,
        $stage = 'requested'
    );

    /**
     * Update an OAuth session
     *
     * Example SQL query:
     *
     * <code>
     * UPDATE oauth_sessions SET auth_code = $authCode, access_token =
     *  $accessToken, stage = $stage, last_updated = UNIX_TIMESTAMP(NOW()) WHERE
     *  id = $sessionId
     * </code>
     *
     * @param  string $sessionId         The session ID
     * @param  string $authCode          The authorisation code (default = "null")
     * @param  string $accessToken       The access token (default = "null")
     * @param  string $refreshToken      The refresh token (default = "null")
     * @param  int    $accessTokenExpire The expiry time of an access token as a unix timestamp
     * @param  string $stage             The stage of the session (default ="request")
     * @return  void
     */
    public function updateSession(
        $sessionId,
        $authCode = null,
        $accessToken = null,
        $refreshToken = null,
        $accessTokenExpire = null,
        $stage = 'requested'
    );

    /**
     * Delete an OAuth session
     *
     * <code>
     * DELETE FROM oauth_sessions WHERE client_id = $clientId AND owner_type =
     *  $type AND owner_id = $typeId
     * </code>
     *
     * @param  string $clientId The client ID
     * @param  string $type     The session owner's type
     * @param  string $typeId   The session owner's ID
     * @return  void
     */
    public function deleteSession(
        $clientId,
        $type,
        $typeId
    );

    /**
     * Validate that an authorisation code is valid
     *
     * Example SQL query:
     *
     * <code>
     * SELECT id FROM oauth_sessions WHERE client_id = $clientID AND
     *  redirect_uri = $redirectUri AND auth_code = $authCode
     * </code>
     *
     * @param  string     $clientId    The client ID
     * @param  string     $redirectUri The redirect URI
     * @param  string     $authCode    The authorisation code
     * @return  int|bool   Returns the session ID if the auth code
     *  is valid otherwise returns false
     */
    public function validateAuthCode(
        $clientId,
        $redirectUri,
        $authCode
    );

    /**
     * Validate an access token
     *
     * Example SQL query:
     *
     * <code>
     * SELECT id, owner_id, owner_type FROM oauth_sessions WHERE access_token = $accessToken
     * </code>
     *
     * Response:
     *
     * <code>
     * Array
     * (
     *     [id] => (int) The session ID
     *     [owner_type] => (string) The owner type
     *     [owner_id] => (string) The owner ID
     * )
     * </code>
     *
     * @param  [type] $accessToken [description]
     * @return [type]              [description]
     */
    public function validateAccessToken($accessToken);

    /**
     * Return the access token for a given session
     *
     * Example SQL query:
     *
     * <code>
     * SELECT access_token FROM oauth_sessions WHERE id = $sessionId
     * </code>
     *
     * @param  int         $sessionId The OAuth session ID
     * @return string|null            Returns the access token as a string if
     *  found otherwise returns null
     */
    public function getAccessToken($sessionId);

    /**
     * Validate a refresh token
     * @param  string $refreshToken The refresh token
     * @param  string $clientId     The client ID
     * @return int                  The session ID
     */
    public function validateRefreshToken($refreshToken, $clientId);

    /**
     * Update the refresh token
     *
     * Example SQL query:
     *
     * <code>
     * UPDATE oauth_sessions SET access_token = $newAccessToken, refresh_token =
     *  $newRefreshToken, access_toke_expires = $accessTokenExpires, last_updated = UNIX_TIMESTAMP(NOW()) WHERE
     *  id = $sessionId
     * </code>
     *
     * @param  string $sessionId             The session ID
     * @param  string $newAccessToken        The new access token for this session
     * @param  string $newRefreshToken       The new refresh token for the session
     * @param  int    $accessTokenExpires    The UNIX timestamp of when the new token expires
     * @return void
     */
    public function updateRefreshToken(
        $sessionId,
        $newAccessToken,
        $newRefreshToken,
        $accessTokenExpires
    );

    /**
     * Associates a session with a scope
     *
     * Example SQL query:
     *
     * <code>
     * INSERT INTO oauth_session_scopes (session_id, scope_id) VALUE ($sessionId,
     *  $scopeId)
     * </code>
     *
     * @param int    $sessionId The session ID
     * @param string $scopeId   The scope ID
     * @return void
     */
    public function associateScope($sessionId, $scopeId);

    /**
     * Return the scopes associated with an access token
     *
     * Example SQL query:
     *
     * <code>
     * SELECT oauth_scopes.scope FROM oauth_session_scopes JOIN oauth_scopes ON
     *  oauth_session_scopes.scope_id = oauth_scopes.id WHERE
     *  session_id = $sessionId
     * </code>
     *
     * Response:
     *
     * <code>
     * Array
     * (
     *     [0] => (string) The scope
     *     [1] => (string) The scope
     *     [2] => (string) The scope
     *     ...
     *     ...
     * )
     * </code>
     *
     * @param  int   $sessionId The session ID
     * @return array
     */
    public function getScopes($sessionId);
}
