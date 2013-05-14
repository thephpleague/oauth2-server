<?php

use \League\OAuth2\Server\Storage\SessionInterface;

class Session implements SessionInterface
{
    public function createSession($clientId, $ownerType, $ownerId)
    {
        return DB::table('oauth_sessions')->insertGetId(array(
            'client_id'         => $clientId,
            'owner_type'        => $ownerType,
            'owner_id'          => $ownerId
        ));
    }

    public function deleteSession($clientId, $ownerType, $ownerId)
    {
        DB::table('oauth_sessions')
            ->where('client_id', $clientId)
            ->where('owner_type', $ownerType)
            ->where('owner_id', $ownerId)
            ->delete();
    }

    public function associateRedirectUri($sessionId, $redirectUri)
    {
        DB::table('oauth_session_redirects')->insert(array(
            'session_id'    => $sessionId,
            'redirect_uri'  => $redirectUri,
        ));
    }

    public function associateAccessToken($sessionId, $accessToken, $expireTime)
    {
        return DB::table('oauth_session_access_tokens')->insertGetId(array(
            'session_id'            => $sessionId,
            'access_token'          => $accessToken,
            'access_token_expires'  => $expireTime,
        ));
    }

    public function associateRefreshToken($accessTokenId, $refreshToken, $expireTime, $clientId)
    {
        DB::table('oauth_session_refresh_tokens')->insert(array(
            'session_access_token_id'  => $accessTokenId,
            'refresh_token'            => $refreshToken,
            'refresh_token_expires'    => $expireTime,
            'client_id'                => $clientId,
        ));
    }

    public function associateAuthCode($sessionId, $authCode, $expireTime, $scopeIds = null)
    {
        DB::table('oauth_session_authcodes')->insert(array(
            'session_id'        => $sessionId,
            'auth_code'         => $authCode,
            'auth_code_expires' => $expireTime,
            'scope_ids'         => $scopeIds,
        ));
    }

    public function removeAuthCode($sessionId)
    {
        DB::table('oauth_session_authcodes')
            ->where('session_id', $sessionId)
            ->delete();
    }

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

    public function validateAccessToken($accessToken)
    {
        $result = DB::table('oauth_session_access_tokens')
            ->join('oauth_sessions', 'oauth_session_access_tokens.session_id', '=', 'oauth_sessions.id')
            ->where('access_token', $accessToken)
            ->where('access_token_expires', '>=', time())
            ->first();

        return (is_null($result)) ? false : (array) $result;
    }

    public function validateRefreshToken($refreshToken, $clientId)
    {
        $result = DB::table('oauth_session_refresh_tokens')
            ->where('refresh_token', $refreshToken)
            ->where('client_id', $clientId)
            ->where('refresh_token_expires', '>=', time())
            ->first();

        return (is_null($result)) ? false : $result->session_access_token_id;
    }

    public function getAccessToken($accessTokenId)
    {
        $result = DB::table('oauth_session_access_tokens')
            ->where('id', $accessTokenId)
            ->first();

        return (is_null($result)) ? false : (array) $result;
    }

    public function associateScope($accessTokenId, $scopeId)
    {
        DB::table('oauth_session_token_scopes')->insert(array(
            'session_access_token_id'   => $accessTokenId,
            'scope_id'                  => $scopeId,
        ));
    }

    public function getScopes($accessToken)
    {
        return DB::table('oauth_session_token_scopes')
            ->join('oauth_session_access_tokens', 'oauth_session_token_scopes.session_access_token_id', '=', 'oauth_session_access_tokens.id')
            ->join('oauth_scopes', 'oauth_session_token_scopes.session_access_token_id', '=', 'oauth_scopes.id')
            ->where('access_token', $accessToken)
            ->get();
    }
}