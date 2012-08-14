<?php

namespace Oauth2\Resource;

interface Database
{
    /**
     * Validate an access token and return the session details.
     * 
     * Database query:
     * 
     * <code>
     * SELECT id, owner_type, owner_id FROM oauth_sessions WHERE access_token =
     *  $accessToken AND stage = 'granted' AND
     *  access_token_expires > UNIX_TIMESTAMP(now())
     * </code>
     * 
     * Response:
     * 
     * <code>
     * Array
     * (
     *     [id] => (int) The session ID
     *     [owner_type] => (string) The session owner type
     *     [owner_id] => (string) The session owner's ID
     * )
     * </code>
     * 
     * @param  string     $accessToken The access token
     * @return array|bool              Return an array on success or false on failure
     */
    public function validateAccessToken($accessToken);

    /**
     * Returns the scopes that the session is authorised with.
     * 
     * Database query:
     * 
     * <code>
     * SELECT scope FROM oauth_session_scopes WHERE access_token =
     *  '291dca1c74900f5f252de351e0105aa3fc91b90b'
     * </code>
     * 
     * Response:
     * 
     * <code>
     * Array
     * (
     *      [0] => (string) A scope
     *      [1] => (string) Another scope
     *      ...
     * )
     * </code>
     * 
     * @param  int   $sessionId The session ID
     * @return array            A list of scopes
     */
    public function sessionScopes($sessionId);
}