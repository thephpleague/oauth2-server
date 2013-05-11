<?php

use \League\OAuth2\Server\Storage\SessionInterface;

class Session implements SessionInterface
{
    /**
     * Create a new session
     * @param  string $clientId  The client ID
     * @param  string $ownerType The type of the session owner (e.g. "user")
     * @param  string $ownerId   The ID of the session owner (e.g. "123")
     * @return int               The session ID
     */
    public function createSession($clientId, $ownerType, $ownerId)
    {
        return DB::table('oauth_sessions')->insertGetId([
            'client_id'         => $clientId,
            'owner_type'        => $ownerType,
            'owner_id'          => $ownerId
        ]);
    }

    /**
     * Delete a session
     * @param  string $clientId  The client ID
     * @param  string $ownerType The type of the session owner (e.g. "user")
     * @param  string $ownerId   The ID of the session owner (e.g. "123")
     * @return void
     */
    public function deleteSession($clientId, $ownerType, $ownerId)
    {
        DB::table('oauth_sessions')
            ->where('client_id', $clientId)
            ->where('owner_type', $ownerType)
            ->where('owner_id', $ownerId)
            ->delete();
    }

    /**
     * Associate a redirect URI with a session
     * @param  int    $sessionId   The session ID
     * @param  string $redirectUri The redirect URI
     * @return void
     */
    public function associateRedirectUri($sessionId, $redirectUri)
    {
        DB::table('oauth_session_redirects')->insert([
            'session_id'    => $sessionId,
            'redirect_uri'  => $redirectUri,
        ]);
    }

    /**
     * Associate an access token with a session
     * @param  int    $sessionId   The session ID
     * @param  string $accessToken The access token
     * @param  int    $expireTime  Unix timestamp of the access token expiry time
     * @return int
     */
    public function associateAccessToken($sessionId, $accessToken, $expireTime)
    {
        return DB::table('oauth_session_access_tokens')->insertGetId([
            'session_id'            => $sessionId,
            'access_token'          => $accessToken,
            'access_token_expires'  => $expireTime,
        ]);
    }

    /**
     * Associate a refresh token with a session
     * @param  int    $accessTokenId The access token ID
     * @param  string $refreshToken  The refresh token
     * @return void
     */
    public function associateRefreshToken($accessTokenId, $refreshToken, $expireTime, $clientId)
    {
        DB::table('oauth_session_refresh_tokens')->insert([
            'session_access_token_id'  => $accessTokenId,
            'refresh_token'            => $refreshToken,
            'refresh_token_expires'    => $expireTime,
            'client_id'                => $clientId,
        ]);
    }

    /**
     * Assocate an authorization code with a session
     * @param  int    $sessionId  The session ID
     * @param  string $authCode   The authorization code
     * @param  int    $expireTime Unix timestamp of the access token expiry time
     * @param  string $scopeIds   Comma seperated list of scope IDs to be later associated (default = null)
     * @return void
     */
    public function associateAuthCode($sessionId, $authCode, $expireTime, $scopeIds = null)
    {
        DB::table('oauth_session_authcodes')->insert([
            'session_id'        => $sessionId,
            'auth_code'         => $authCode,
            'auth_code_expires' => $expireTime,
            'scope_ids'         => $scopeIds,
        ]);
    }

    /**
     * Remove an associated authorization token from a session
     * @param  int    $sessionId   The session ID
     * @return void
     */
    public function removeAuthCode($sessionId)
    {
        DB::table('oauth_session_authcodes')
            ->where('session_id', $sessionId)
            ->delete();
    }

    /**
     * Validate an authorization code
     * @param  string $clientId    The client ID
     * @param  string $redirectUri The redirect URI
     * @param  string $authCode    The authorization code
     * @return void
     */
    public function validateAuthCode($clientId, $redirectUri, $authCode)
    {
        $result = DB::table('oauth_sessions')
            ->select('oauth_sessions.id, oauth_session_authcodes.scope_ids')
            ->join('oauth_session_authcodes', 'oauth_sessions.id', '=', 'oauth_session_authcodes.session_id')
            ->join('oauth_session_redirects', 'oauth_sessions.id', '=', 'oauth_session_redirects.session_id')
            ->where('oauth_sessions.client_id', $clientId)
            ->where('oauth_session_authcodes.auth_code', $authCode)
            ->where('oauth_session_authcodes.auth_code_expires', '>=', time())
            ->where('oauth_session_redirects.redirect_uri', $redirectUri)
            ->first();

        return (is_null($result)) ? false : (array) $result;
    }

    /**
     * Validate an access token
     * @param  string $accessToken The access token to be validated
     * @return void
     */
    public function validateAccessToken($accessToken)
    {
        $result = DB::table('oauth_session_access_tokens')
            ->join('oauth_sessions', 'oauth_session_access_tokens.session_id', '=', 'oauth_sessions.id')
            ->where('access_token', $accessToken)
            ->where('access_token_expires', '>=', time())
            ->first();

        return (is_null($result)) ? false : (array) $result;
    }

    /**
     * Validate a refresh token
     * @param  string $refreshToken The access token
     * @return void
     */
    public function validateRefreshToken($refreshToken, $clientId)
    {
        $result = DB::table('oauth_session_refresh_tokens')
            ->where('refresh_token', $refreshToken)
            ->where('client_id', $clientId)
            ->where('refresh_token_expires', '>=', time())
            ->first();

        return (is_null($result)) ? false : $result->session_access_token_id;
    }

    /**
     * Get an access token by ID
     * @param  int    $accessTokenId The access token ID
     * @return array
     */
    public function getAccessToken($accessTokenId)
    {
        $result = DB::table('oauth_session_access_tokens')
            ->where('id', $accessTokenId)
            ->first();

        return (is_null($result)) ? false : (array) $result;
    }

    /**
     * Associate a scope with an access token
     * @param  int    $accessTokenId The ID of the access token
     * @param  int    $scopeId       The ID of the scope
     * @return void
     */
    public function associateScope($accessTokenId, $scopeId) 
    {
        DB::table('oauth_session_token_scopes')->insert([
            'session_access_token_id'   => $accessTokenId,
            'scope_id'                  => $scopeId,
        ]);
    }

    /**
     * Get all associated access tokens for an access token
     * @param  string $accessToken The access token
     * @return array
     */
    public function getScopes($accessToken)
    {
        return DB::table('oauth_session_token_scopes')
            ->join('oauth_session_access_tokens', 'oauth_session_token_scopes.session_access_token_id', '=', 'oauth_session_access_tokens.id')
            ->join('oauth_scopes', 'oauth_session_token_scopes.session_access_token_id', '=', 'oauth_scopes.id')
            ->where('access_token', $accessToken)
            ->get();
    }
}