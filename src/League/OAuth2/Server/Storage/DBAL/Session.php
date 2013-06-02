<?php
/**
 * @author Matt Robinson <matt@inanimatt.com>
 */
namespace League\OAuth2\Server\Storage\DBAL;

use League\OAuth2\Server\Storage\SessionInterface;

class Session implements SessionInterface
{
    protected $db;

    public function __construct($db)
    {
        $this->db = $db;
    }

    public function createSession($clientId, $ownerType, $ownerId)
    {
        $this->db->insert('oauth_sessions', array(
            'client_id'  => $clientId,
            'owner_type' => $ownerType,
            'owner_id'   => $ownerId,
        ));

        return $this->db->lastInsertId();
    }

    public function deleteSession($clientId, $ownerType, $ownerId)
    {
        $this->db->delete('oauth_sessions', array(
            'client_id'  => $clientId,
            'owner_type' => $ownerType,
            'owner_id'   => $ownerId,
        ));
    }

    public function associateRedirectUri($sessionId, $redirectUri)
    {
        $this->db->insert('oauth_session_redirects', array(
            'session_id'   => $sessionId,
            'redirect_uri' => $redirectUri,
        ));
    }

    public function associateAccessToken($sessionId, $accessToken, $expireTime)
    {
        $this->db->insert('oauth_session_access_tokens', array(
            'session_id'           => $sessionId,
            'access_token'         => $accessToken,
            'access_token_expires' => $expireTime,
        ));

        return $this->db->lastInsertId();
    }

    public function associateRefreshToken($accessTokenId, $refreshToken, $expireTime, $clientId)
    {
        $this->db->insert('oauth_session_refresh_tokens', array(
            'session_access_token_id' => $accessTokenId,
            'refresh_token'           => $refreshToken,
            'refresh_token_expires'   => $expireTime,
            'client_id'               => $clientId,
        ));
    }

    public function associateAuthCode($sessionId, $authCode, $expireTime)
    {
        $this->db->insert('oauth_session_authcodes', array(
            'session_id'        => $sessionId,
            'auth_code'         => $authCode,
            'auth_code_expires' => $expireTime,
        ));

        return $this->db->lastInsertId();
    }

    public function removeAuthCode($sessionId)
    {
        $this->db->delete('oauth_session_authcodes', array(
            'session_id' => $sessionId,
        ));
    }

    public function validateAuthCode($clientId, $redirectUri, $authCode)
    {
        $stmt = $this->db->prepare('SELECT oauth_sessions.id AS session_id, oauth_session_authcodes.id AS authcode_id
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

        $result = $stmt->fetch(\PDO::FETCH_OBJ);

        return ($result === false) ? false : (array) $result;
    }

    public function validateAccessToken($accessToken)
    {
        $stmt = $this->db->prepare('SELECT session_id, oauth_sessions.`client_id`, oauth_sessions.`owner_id`, oauth_sessions.`owner_type` FROM `oauth_session_access_tokens` JOIN oauth_sessions ON oauth_sessions.`id` = session_id WHERE  access_token = :accessToken AND access_token_expires >= ' . time());
        $stmt->bindValue(':accessToken', $accessToken);
        $stmt->execute();

        $result = $stmt->fetch(\PDO::FETCH_OBJ);
        return ($result === false) ? false : (array) $result;
    }

    public function removeRefreshToken($refreshToken)
    {
        $this->db->delete('oauth_session_refresh_tokens', array(
            'refresh_token' => $refreshToken,
        ));
    }

    public function validateRefreshToken($refreshToken, $clientId)
    {
        $stmt = $this->db->prepare('SELECT session_access_token_id FROM `oauth_session_refresh_tokens` WHERE
         refresh_token = :refreshToken AND client_id = :clientId AND refresh_token_expires >= ' . time());
        $stmt->bindValue(':refreshToken', $refreshToken);
        $stmt->bindValue(':clientId', $clientId);
        $stmt->execute();

        $result = $stmt->fetch(\PDO::FETCH_OBJ);
        return ($result === false) ? false : $result->session_access_token_id;
    }

    public function getAccessToken($accessTokenId)
    {
        $stmt = $this->db->prepare('SELECT * FROM `oauth_session_access_tokens` WHERE `id` = :accessTokenId');
        $stmt->bindValue(':accessTokenId', $accessTokenId);
        $stmt->execute();

        $result = $stmt->fetch(\PDO::FETCH_OBJ);
        return ($result === false) ? false : (array) $result;
    }

    public function associateAuthCodeScope($authCodeId, $scopeId)
    {
        $this->db->insert('oauth_session_authcode_scopes', array(
            'oauth_session_authcode_id' => $authCodeId,
            'scope_id' => $scopeId,
        ));
    }

    public function getAuthCodeScopes($oauthSessionAuthCodeId)
    {
        $stmt = $db->prepare('SELECT scope_id FROM `oauth_session_authcode_scopes` WHERE oauth_session_authcode_id = :authCodeId');
        $stmt->bindValue(':authCodeId', $oauthSessionAuthCodeId);
        $stmt->execute();

        return $stmt->fetchAll();
    }

    public function associateScope($accessTokenId, $scopeId)
    {
        $this->db->insert('oauth_session_token_scopes', array(
            'session_access_token_id' => $accessTokenId,
            'scope_id' => $scopeId,
        ));
    }

    public function getScopes($accessToken)
    {
        $stmt = $this->db->prepare('SELECT oauth_scopes.* FROM oauth_session_token_scopes JOIN oauth_session_access_tokens ON oauth_session_access_tokens.`id` = `oauth_session_token_scopes`.`session_access_token_id` JOIN oauth_scopes ON oauth_scopes.id = `oauth_session_token_scopes`.`scope_id` WHERE access_token = :accessToken');
        $stmt->bindValue(':accessToken', $accessToken);
        $stmt->execute();

        return $stmt->fetchAll();
    }
}