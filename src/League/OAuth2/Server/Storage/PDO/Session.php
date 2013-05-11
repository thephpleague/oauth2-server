<?php

namespace League\OAuth2\Server\Storage\PDO;

use League\OAuth2\Server\Storage\SessionInterface;

class Session implements SessionInterface
{
    public function createSession($clientId, $ownerType, $ownerId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_sessions (client_id, owner_type,  owner_id) VALUE
         (:clientId, :ownerType, :ownerId)');
        $stmt->bindValue(':clientId', $clientId);
        $stmt->bindValue(':ownerType', $ownerType);
        $stmt->bindValue(':ownerId', $ownerId);
        $stmt->execute();

        return $db->lastInsertId();
    }

    public function deleteSession($clientId, $ownerType, $ownerId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('DELETE FROM oauth_sessions WHERE client_id = :clientId AND
         owner_type = :type AND owner_id = :typeId');
        $stmt->bindValue(':clientId', $clientId);
        $stmt->bindValue(':type', $ownerType);
        $stmt->bindValue(':typeId', $ownerId);
        $stmt->execute();
    }

    public function associateRedirectUri($sessionId, $redirectUri)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_session_redirects (session_id, redirect_uri)
         VALUE (:sessionId, :redirectUri)');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->bindValue(':redirectUri', $redirectUri);
        $stmt->execute();
    }

    public function associateAccessToken($sessionId, $accessToken, $expireTime)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_session_access_tokens (session_id, access_token, access_token_expires)
         VALUE (:sessionId, :accessToken, :accessTokenExpire)');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->bindValue(':accessToken', $accessToken);
        $stmt->bindValue(':accessTokenExpire', $expireTime);
        $stmt->execute();

        return $db->lastInsertId();
    }

    public function associateRefreshToken($accessTokenId, $refreshToken, $expireTime, $clientId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_session_refresh_tokens (session_access_token_id, refresh_token, refresh_token_expires, client_id) VALUE
         (:accessTokenId, :refreshToken, :expireTime, :clientId)');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->bindValue(':refreshToken', $refreshToken);
        $stmt->bindValue(':expireTime', $expireTime);
        $stmt->bindValue(':clientId', $clientId);
        $stmt->execute();
    }

    public function associateAuthCode($sessionId, $authCode, $expireTime)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_session_authcodes (session_id, auth_code, auth_code_expires)
         VALUE (:sessionId, :authCode, :authCodeExpires)');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->bindValue(':authCode', $authCode);
        $stmt->bindValue(':authCodeExpires', $expireTime);
        $stmt->execute();

        return $db->lastInsertId();
    }

    public function removeAuthCode($sessionId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('DELETE FROM oauth_session_authcodes WHERE session_id = :sessionId');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->execute();
    }

    public function validateAuthCode($clientId, $redirectUri, $authCode)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT oauth_sessions.id AS session_id, oauth_session_authcodes.id AS authcode_id
         FROM oauth_sessions JOIN oauth_session_authcodes ON oauth_session_authcodes.`session_id`
          = oauth_sessions.id JOIN oauth_session_redirects ON oauth_session_redirects.`session_id`
          = oauth_sessions.id WHERE oauth_sessions.client_id = :clientId AND oauth_session_authcodes.`auth_code`
          = :authCode AND  `oauth_session_authcodes`.`auth_code_expires` >= :time AND
           `oauth_session_redirects`.`redirect_uri` = :redirectUri');
        $stmt->bindValue(':clientId', $clientId);
        $stmt->bindValue(':redirectUri', $redirectUri);
        $stmt->bindValue(':authCode', $authCode);
        $stmt->bindValue(':time', time());
        $stmt->execute();

        $result = $stmt->fetchObject();

        return ($result === false) ? false : (array) $result;
    }

    public function validateAccessToken($accessToken)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT session_id, oauth_sessions.`client_id`, oauth_sessions.`owner_id`, oauth_sessions.`owner_type` FROM `oauth_session_access_tokens` JOIN oauth_sessions ON oauth_sessions.`id` = session_id WHERE  access_token = :accessToken AND access_token_expires >= ' . time());
        $stmt->bindValue(':accessToken', $accessToken);
        $stmt->execute();

        $result = $stmt->fetchObject();
        return ($result === false) ? false : (array) $result;
    }

    public function removeRefreshToken($refreshToken)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('DELETE FROM `oauth_session_refresh_tokens` WHERE refresh_token = :refreshToken');
        $stmt->bindValue(':refreshToken', $refreshToken);
        $stmt->execute();
    }

    public function validateRefreshToken($refreshToken, $clientId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT session_access_token_id FROM `oauth_session_refresh_tokens` WHERE
         refresh_token = :refreshToken AND client_id = :clientId AND refresh_token_expires >= ' . time());
        $stmt->bindValue(':refreshToken', $refreshToken);
        $stmt->bindValue(':clientId', $clientId);
        $stmt->execute();

        $result = $stmt->fetchObject();
        return ($result === false) ? false : $result->session_access_token_id;
    }

    public function getAccessToken($accessTokenId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT * FROM `oauth_session_access_tokens` WHERE `id` = :accessTokenId');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->execute();

        $result = $stmt->fetchObject();
        return ($result === false) ? false : (array) $result;
    }

    public function associateAuthCodeScope($authCodeId, $scopeId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO `oauth_session_authcode_scopes` (`oauth_session_authcode_id`, `scope_id`) VALUES (:authCodeId, :scopeId)');
        $stmt->bindValue(':authCodeId', $authCodeId);
        $stmt->bindValue(':scopeId', $scopeId);
        $stmt->execute();
    }

    public function getAuthCodeScopes($oauthSessionAuthCodeId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT scope_id FROM `oauth_session_authcode_scopes` WHERE oauth_session_authcode_id = :authCodeId');
        $stmt->bindValue(':authCodeId', $oauthSessionAuthCodeId);
        $stmt->execute();

        return $stmt->fetchAll();
    }

    public function associateScope($accessTokenId, $scopeId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO `oauth_session_token_scopes` (`session_access_token_id`, `scope_id`)
         VALUE (:accessTokenId, :scopeId)');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->bindValue(':scopeId', $scopeId);
        $stmt->execute();
    }

    public function getScopes($accessToken)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT oauth_scopes.* FROM oauth_session_token_scopes JOIN oauth_session_access_tokens ON oauth_session_access_tokens.`id` = `oauth_session_token_scopes`.`session_access_token_id` JOIN oauth_scopes ON oauth_scopes.id = `oauth_session_token_scopes`.`scope_id` WHERE access_token = :accessToken');
        $stmt->bindValue(':accessToken', $accessToken);
        $stmt->execute();

        return $stmt->fetchAll();
    }
}