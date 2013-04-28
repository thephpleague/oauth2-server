<?php

namespace OAuth2\Storage\PDO;

use OAuth2\Storage\SessionInterface;

class Session implements SessionInterface
{
    public function createSession($params = array())
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO oauth_sessions (client_id, owner_type,  owner_id) VALUE (:clientId, :ownerType, :ownerId)');
        $stmt->bindValue(':clientId', $params['client_id']);
        $stmt->bindValue(':ownerType', $params['owner_type']);
        $stmt->bindValue(':ownerId', $params['owner_id']);
        $stmt->execute();

        $sessionId = $db->lastInsertId();

        if (isset($params['redirect_uri'])) {
            $stmt = $db->prepare('INSERT INTO oauth_session_redirects (session_id, redirect_uri) VALUE (:sessionId, :redirectUri)');
            $stmt->bindValue(':sessionId', $sessionId);
            $stmt->bindValue(':redirectUri', $params['redirect_uri']);
            $stmt->execute();
        }

        if (isset($params['auth_code'])) {
            $stmt = $db->prepare('INSERT INTO oauth_session_authcodes (session_id, auth_code, auth_code_expires, scope_ids) VALUE (:sessionId, :authCode, :authCodeExpires, :scopeIds)');
            $stmt->bindValue(':sessionId', $sessionId);
            $stmt->bindValue(':authCode', $params['auth_code']);
            $stmt->bindValue(':authCodeExpires', time() + 600);
            $stmt->bindValue(':scopeIds', isset($params['scope_ids']) ? $params['scope_ids'] : null);
            $stmt->execute();
        }

        if (isset($params['access_token'])) {
            $stmt = $db->prepare('INSERT INTO oauth_session_access_tokens (session_id, access_token, access_token_expires) VALUE (:sessionId, :accessToken, :accessTokenExpire)');
            $stmt->bindValue(':sessionId', $sessionId);
            $stmt->bindValue(':accessToken', $params['access_token']);
            $stmt->bindValue(':accessTokenExpire', $params['access_token_expire']);
            $stmt->execute();

            $accessTokenId = $db->lastInsertId();

            if (isset($params['refresh_token']) && $params['refresh_token'] !== null) {
                $stmt = $db->prepare('INSERT INTO oauth_session_refresh_tokens (session_access_token_id, refresh_token) VALUE (:accessTokenId, :refreshToken)');
                $stmt->bindValue(':accessTokenId', $accessTokenId);
                $stmt->bindValue(':refreshToken', $params['refresh_token']);
                $stmt->execute();
            }
        }

        return $sessionId;
    }

    public function updateSession($sessionId, $params = array())
    {
        $db = \ezcDbInstance::get();

        if (isset($params['access_token'])) {
            $stmt = $db->prepare('INSERT INTO oauth_session_access_tokens (session_id, access_token, access_token_expires) VALUE (:sessionId, :accessToken, :accessTokenExpire)');
            $stmt->bindValue(':sessionId', $sessionId);
            $stmt->bindValue(':accessToken', $params['access_token']);
            $stmt->bindValue(':accessTokenExpire', $params['access_token_expire']);
            $stmt->execute();

            $accessTokenId = $db->lastInsertId();

            if (isset($params['refresh_token']) && $params['refresh_token'] !== null) {
                $stmt = $db->prepare('INSERT INTO oauth_session_refresh_tokens (session_access_token_id, refresh_token) VALUE (:accessTokenId, :refreshToken)');
                $stmt->bindValue(':accessTokenId', $accessTokenId);
                $stmt->bindValue(':refreshToken', $params['refresh_token']);
                $stmt->execute();
            }

            return $accessTokenId;
        }
    }

    public function deleteSession($clientId, $type, $typeId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('DELETE FROM oauth_sessions WHERE client_id = :clientId AND owner_type = :type AND owner_id = :typeId');
        $stmt->bindValue(':clientId', $clientId);
        $stmt->bindValue(':type', $type);
        $stmt->bindValue(':typeId', $typeId);
        $stmt->execute();
    }

    public function validateAuthCode($clientId, $redirectUri, $authCode)
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

    public function deleteAuthCode($sessionId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('DELETE FROM oauth_session_authcodes WHERE session_id = :sessionId');
        $stmt->bindValue(':sessionId', $sessionId);
        $stmt->execute();
    }

    public function validateAccessToken($accessToken)
    {
        throw new \Exception('Not implemented '.debug_backtrace()[0]['function']);
    }

    public function getAccessToken($sessionId)
    {
        throw new \Exception('Not implemented '.debug_backtrace()[0]['function']);
    }

    public function validateRefreshToken($refreshToken, $clientId)
    {
        throw new \Exception('Not implemented '.debug_backtrace()[0]['function']);
    }

    public function updateRefreshToken($sessionId, $newAccessToken, $newRefreshToken, $accessTokenExpires)
    {
        throw new \Exception('Not implemented '.debug_backtrace()[0]['function']);
    }

    public function associateScope($accessTokenId, $scopeId)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('INSERT INTO `oauth_session_token_scopes` (`session_access_token_id`, `scope_id`) VALUE (:accessTokenId, :scopeId)');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->bindValue(':scopeId', $scopeId);
        $stmt->execute();
    }

    public function getScopes($sessionId)
    {
        throw new \Exception('Not implemented '.debug_backtrace()[0]['function']);
    }
}