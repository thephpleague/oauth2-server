<?php

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
     * @param  string $clientId     The client ID
     * @param  string $redirectUri  The redirect URI
     * @param  string $type         The session owner's type (default = "user")
     * @param  string $typeId       The session owner's ID (default = "null")
     * @param  string $authCode     The authorisation code (default = "null")
     * @param  string $accessToken  The access token (default = "null")
     * @param  string $refreshToken The refresh token (default = "null")
     * @param  string $stage        The stage of the session (default ="request")
     * @return  int The session ID
     */
    public function create(
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
     * @param  string $sessionId    The session ID
     * @param  string $authCode     The authorisation code (default = "null")
     * @param  string $accessToken  The access token (default = "null")
     * @param  string $refreshToken The refresh token (default = "null")
     * @param  string $stage        The stage of the session (default ="request")
     * @return  void
     */
    public function update(
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
    public function delete(
        $clientId,
        $type,
        $typeId
    );

    /**
     * Return the session ID for a given session owner and client combination
     *
     * Example SQL query:
     *
     * <code>
     * SELECT id FROM oauth_sessions WHERE client_id = $clientId
     *  AND owner_type = $type AND owner_id = $typeId
     * </code>
     *
     * @param  string      $type     The session owner's type
     * @param  string      $typeId   The session owner's ID
     * @param  string      $clientId The client ID
     * @return string|null           Return the session ID as an integer if
     *  found otherwise returns false
     */
    public function exists(
        $type,
        $typeId,
        $clientId
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
     * Response:
     *
     * <code>
     * Array
     * (
     *     [id] => (int) The session ID
     *     [client_id] => (string) The client ID
     *     [redirect_uri] => (string) The redirect URI
     *     [owner_type] => (string) The session owner type
     *     [owner_id] => (string) The session owner's ID
     *     [auth_code] => (string) The authorisation code
     *     [stage] => (string) The session's stage
     *     [first_requested] => (int) Unix timestamp of the time the session was
     *      first generated
     *     [last_updated] => (int) Unix timestamp of the time the session was
     *      last updated
     * )
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
     * Removes an authorisation code associated with a session
     *
     * Example SQL query:
     *
     * <code>
     * UPDATE oauth_sessions SET auth_code = NULL WHERE id = $sessionId
     * </code>
     *
     * @param  int    $sessionId The OAuth session ID
     * @return void
     */
    public function removeAuthCode($sessionId);

    /**
     * Sets a sessions access token
     *
     * Example SQL query:
     *
     * <code>
     * UPDATE oauth_sessions SET access_token = $accessToken WHERE id =
     *  $sessionId
     * </code>
     *
     * @param int    $sessionId   The OAuth session ID
     * @param string $accessToken The access token
     * @return void
     */
    public function setAccessToken(
        $sessionId,
        $accessToken
    );

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
    public function updateRefreshToken($sessionId, $newAccessToken, $newRefreshToken, $accessTokenExpires);

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
     * @param string $scope     The scope ID
     * @return void
     */
    public function associateScope($sessionId, $scopeId);

    /**
     * Return the scopes associated with an access token
     *
     * Example SQL query:
     *
     * <code>
     * SELECT scopes.scope, scopes.name, scopes.description FROM
     * oauth_session_scopes JOIN scopes ON oauth_session_scopes.scope =
     *  scopes.scope WHERE access_token = $accessToken
     * </code>
     *
     * Response:
     *
     * <code>
     * Array
     * (
     *     [0] => Array
     *         (
     *             [scope] => (string) The scope
     *             [name] => (string) The scope's name
     *             [description] => (string) The scope's description
     *         )
     * )
     * </code>
     *
     * @param  string $accessToken The access token
     * @return array
     */
    public function getScopes($accessToken);
}
