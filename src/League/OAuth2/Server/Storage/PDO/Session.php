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

        $stmt = $db->prepare('INSERT INTO oauth_redirects (session_id, redirect_uri)
         VALUE (:sessionId, :redirectUri)');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->bindValue(':redirectUri', $redirectUri);
        $stmt->execute();
    }

    public function associateAccessToken($sessionId, $accessToken, $expireTime)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_access_tokens (session_id, access_token, access_token_expires)
         VALUE (:sessionId, :accessToken, :accessTokenExpire)');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->bindValue(':accessToken', $accessToken);
        $stmt->bindValue(':accessTokenExpire', $expireTime);
        $stmt->execute();

        return $db->lastInsertId();
    }

    public function associateRefreshToken($accessTokenId, $refreshToken, $expireTime)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_refresh_tokens (access_token_id, refresh_token, refresh_token_expires) VALUE
         (:accessTokenId, :refreshToken, :expireTime)');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->bindValue(':refreshToken', $refreshToken);
        $stmt->bindValue(':expireTime', $expireTime);
        $stmt->execute();
    }

    public function associateAuthCode($sessionId, $authCode, $expireTime)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_authcodes (session_id, auth_code, auth_code_expires)
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

        $stmt = $db->prepare('DELETE FROM oauth_authcodes WHERE session_id = :sessionId');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->execute();
    }

    public function validateAuthCode($clientId, $redirectUri, $authCode)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT oauth_sessions.id AS session_id, oauth_authcodes.id AS authcode_id
         FROM oauth_sessions JOIN oauth_authcodes ON oauth_authcodes.`session_id`
          = oauth_sessions.id JOIN oauth_redirects ON oauth_redirects.`session_id`
          = oauth_sessions.id WHERE oauth_sessions.client_id = :clientId AND oauth_authcodes.`auth_code`
          = :authCode AND  `oauth_authcodes`.`auth_code_expires` >= :time AND
           `oauth_redirects`.`redirect_uri` = :redirectUri');
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

        $stmt = $db->prepare('SELECT session_id, oauth_sessions.`client_id`, oauth_sessions.`owner_id`, oauth_sessions.`owner_type` FROM `oauth_access_tokens` JOIN oauth_sessions ON oauth_sessions.`id` = session_id WHERE  access_token = :accessToken AND access_token_expires >= ' . time());
        $stmt->bindValue(':accessToken', $accessToken);
        $stmt->execute();

        $result = $stmt->fetchObject();
        return ($result === false) ? false : (array) $result;
    }

    public function removeRefreshToken($refreshToken)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('DELETE FROM `oauth_refresh_tokens` WHERE refresh_token = :refreshToken');
        $stmt->bindValue(':refreshToken', $refreshToken);
        $stmt->execute();
    }

    public function validateRefreshToken($refreshToken, $clientId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT t3.session_token_id FROM `oauth_sessions` JOIN `oauth_access_tokens` ON oauth_access_tokens.session_id = oauth_sessions.id JOIN `oauth_refresh_tokens` ON oauth_refresh_tokens.access_token_id = oauth_access_tokens.id AND oauth_refresh_tokens.refresh_token = :refreshToken AND oauth_refresh_tokens.refresh_token_expires >= :time WHERE t1.client_id = :clientId');
        $stmt->bindValue(':refreshToken', $refreshToken);
        $stmt->bindValue(':clientId', $clientId);
        $stmt->bindValue(':time', time());
        $stmt->execute();

        $result = $stmt->fetchObject();
        return ($result === false) ? false : $result->access_token_id;
    }

    public function getAccessToken($accessTokenId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT * FROM `oauth_access_tokens` WHERE `id` = :accessTokenId');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->execute();

        $result = $stmt->fetchObject();
        return ($result === false) ? false : (array) $result;
    }

    public function associateAuthCodeScope($authCodeId, $scopeId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO `oauth_authcode_scopes` (`authcode_id`, `scope_id`) VALUES (:authCodeId, :scopeId)');
        $stmt->bindValue(':authCodeId', $authCodeId);
        $stmt->bindValue(':scopeId', $scopeId);
        $stmt->execute();
    }

    public function getAuthCodeScopes($authCodeId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT scope_id FROM `oauth_authcode_scopes` WHERE authcode_id = :authCodeId');
        $stmt->bindValue(':authCodeId', $authCodeId);
        $stmt->execute();

        return $stmt->fetchAll();
    }

    public function associateScope($accessTokenId, $scopeId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO `oauth_access_token_scopes` (`access_token_id`, `scope_id`)
         VALUE (:accessTokenId, :scopeId)');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->bindValue(':scopeId', $scopeId);
        $stmt->execute();
    }

    public function getScopes($accessToken)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT oauth_scopes.* FROM oauth_access_token_scopes JOIN oauth_access_tokens ON oauth_access_tokens.`id` = `oauth_access_token_scopes`.`access_token_id` JOIN oauth_scopes ON oauth_scopes.id = `oauth_access_token_scopes`.`scope_id` WHERE access_token = :accessToken');
        $stmt->bindValue(':accessToken', $accessToken);
        $stmt->execute();

        return $stmt->fetchAll();
    }
}
