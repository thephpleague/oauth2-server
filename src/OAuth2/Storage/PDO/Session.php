<?php

namespace OAuth2\Storage\PDO;

use OAuth2\Storage\SessionInterface;

class Session implements SessionInterface
{
    /**
     * Create a new session
     * @param  string $clientId  The client ID
     * @param  string $ownerType The type of the session owner (e.g. "user")
     * @param  string $ownerId   The ID of the session owner (e.g. "123")
     * @return int               The session ID
     */
    public function createSession(string $clientId, string $ownerType, string $ownerId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_sessions (client_id, owner_type,  owner_id) VALUE (:clientId, :ownerType, :ownerId)');
        $stmt->bindValue(':clientId', $clientId);
        $stmt->bindValue(':ownerType', $ownerType);
        $stmt->bindValue(':ownerId', $ownerId);
        $stmt->execute();

        return $db->lastInsertId();
    }

    /**
     * Delete a session
     * @param  string $clientId  The client ID
     * @param  string $ownerType The type of the session owner (e.g. "user")
     * @param  string $ownerId   The ID of the session owner (e.g. "123")
     * @return void
     */
    public function deleteSession(string $clientId, string $ownerType, string $ownerId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('DELETE FROM oauth_sessions WHERE client_id = :clientId AND owner_type = :type AND owner_id = :typeId');
        $stmt->bindValue(':clientId', $clientId);
        $stmt->bindValue(':type', $ownerType);
        $stmt->bindValue(':typeId', $ownerId);
        $stmt->execute();
    }

    /**
     * Associate a redirect URI with a session
     * @param  int    $sessionId   The session ID
     * @param  string $redirectUri The redirect URI
     * @return void
     */
    public function associateRedirectUri(int $sessionId, string $redirectUri)
    {
        $stmt = $db->prepare('INSERT INTO oauth_session_redirects (session_id, redirect_uri) VALUE (:sessionId, :redirectUri)');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->bindValue(':redirectUri', $redirectUri);
        $stmt->execute();
    }

    /**
     * Remove an associated redirect URI
     * @param  int    $sessionId The session ID
     * @return void
     */
    public function removeRedirectUri(int $sessionId)
    {
        throw new \Exception('Not implemented - ' . debug_backtrace()[0]['function']);
    }

    /**
     * Associate an access token with a session
     * @param  int    $sessionId   The session ID
     * @param  string $accessToken The access token
     * @param  int    $expireTime  Unix timestamp of the access token expiry time
     * @return void
     */
    public function associateAccessToken(int $sessionId, string $accessToken, int $expireTime)
    {
        $stmt = $db->prepare('INSERT INTO oauth_session_access_tokens (session_id, access_token, access_token_expires) VALUE (:sessionId, :accessToken, :accessTokenExpire)');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->bindValue(':accessToken', $accessToken);
        $stmt->bindValue(':accessTokenExpire', $expireTime);
        $stmt->execute();

        return $db->lastInsertId();
    }

    /**
     * Remove an associated access token from a session
     * @param  int    $sessionId   The session ID
     * @return void
     */
    public function removeAccessToken(int $sessionId)
    {
        $stmt = $db->prepare('INSERT INTO oauth_session_refresh_tokens (session_access_token_id, refresh_token) VALUE (:accessTokenId, :refreshToken)');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->bindValue(':refreshToken', $params['refresh_token']);
        $stmt->execute();
    }

    /**
     * Associate a refresh token with a session
     * @param  int    $accessTokenId The access token ID
     * @param  string $refreshToken  The refresh token
     * @return void
     */
    public function associateRefreshToken(int $accessTokenId, string $refreshToken)
    {
        $stmt = $db->prepare('INSERT INTO oauth_session_refresh_tokens (session_access_token_id, refresh_token) VALUE (:accessTokenId, :refreshToken)');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->bindValue(':refreshToken', $refreshToken);
        $stmt->execute();
    }

    /**
     * Remove an associated refresh token from a session
     * @param  int    $sessionId   The session ID
     * @return void
     */
    public function removeRefreshToken(int $sessionId)
    {

    }

    /**
     * Assocate an authorization code with a session
     * @param  int    $sessionId  The session ID
     * @param  string $authCode   The authorization code
     * @param  int    $expireTime Unix timestamp of the access token expiry time
     * @param  string $scopeIds   Comma seperated list of scope IDs to be later associated (default = null)
     * @return void
     */
    public function associateAuthCode(int $sessionId, string $authCode, int $expireTime, string $scopeIds = null)
    {
        $stmt = $db->prepare('INSERT INTO oauth_session_authcodes (session_id, auth_code, auth_code_expires, scope_ids) VALUE (:sessionId, :authCode, :authCodeExpires, :scopeIds)');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->bindValue(':authCode', $authCode);
        $stmt->bindValue(':authCodeExpires', $expireTime);
        $stmt->bindValue(':scopeIds', $scopeIds);
        $stmt->execute();
    }

    /**
     * Remove an associated authorization token from a session
     * @param  int    $sessionId   The session ID
     * @return void
     */
    public function removeAuthCode(int $sessionId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('DELETE FROM oauth_session_authcodes WHERE session_id = :sessionId');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->execute();
    }

    /**
     * Validate an authorization code
     * @param  string $clientId    The client ID
     * @param  string $redirectUri The redirect URI
     * @param  string $authCode    The authorization code
     * @return void
     */
    public function validateAuthCode(string $clientId, string $redirectUri, string $authCode)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT oauth_sessions.id, oauth_session_authcodes.scope_ids FROM oauth_sessions JOIN oauth_session_authcodes ON oauth_session_authcodes.`session_id` = oauth_sessions.id JOIN oauth_session_redirects ON oauth_session_redirects.`session_id` = oauth_sessions.id WHERE oauth_sessions.client_id = :clientId AND oauth_session_authcodes.`auth_code` = :authCode AND `oauth_session_authcodes`.`auth_code_expires` >= :time AND `oauth_session_redirects`.`redirect_uri` = :redirectUri');
        $stmt->bindValue(':clientId', $clientId);
        $stmt->bindValue(':redirectUri', $redirectUri);
        $stmt->bindValue(':authCode', $authCode);
        $stmt->bindValue(':time', time());
        $stmt->execute();

        $result = $stmt->fetchObject();

        return ($result === false) ? false : (array) $result;
    }

    /**
     * Validate an access token
     * @param  string $accessToken [description]
     * @return void
     */
    public function validateAccessToken(string $accessToken)
    {
        throw new \Exception('Not implemented - ' . debug_backtrace()[0]['function']);
    }

    /**
     * Validate a refresh token
     * @param  string $accessToken The access token
     * @return void
     */
    public function validateRefreshToken(string $accessToken)
    {
        throw new \Exception('Not implemented - ' . debug_backtrace()[0]['function']);
    }

    /**
     * Associate a scope with an access token
     * @param  int    $accessTokenId The ID of the access token
     * @param  int    $scopeId       The ID of the scope
     * @return void
     */
    public function associateScope(int $accessTokenId, int $scopeId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO `oauth_session_token_scopes` (`session_access_token_id`, `scope_id`) VALUE (:accessTokenId, :scopeId)');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->bindValue(':scopeId', $scopeId);
        $stmt->execute();
    }

    /**
     * Get all associated access tokens for an access token
     * @param  string $accessToken The access token
     * @return array
     */
    public function getScopes(string $accessToken)
    {
        throw new \Exception('Not implemented - ' . debug_backtrace()[0]['function']);
    }
}