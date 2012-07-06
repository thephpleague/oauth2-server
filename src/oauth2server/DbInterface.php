<?php

interface OAuth2ServerDatabase
{
    public function validateClient(
        string $clientId,
        string $clientSecret = null,
        string $redirectUri = null
    );

    public function newSession(
        string $clientId,
        string $redirectUri,
        $type = 'user',
        string $typeId = null,
        string $authCode = null,
        string $accessToken = null,
        $stage = 'request'
    );

    public function updateSession(
        string $clientId,
        $type = 'user',
        string $typeId = null,
        string $authCode = null,
        string $accessToken = null,
        string $stage
    );

    public function deleteSession(
        string $clientId,
        string $type,
        string $typeId
    );

    public function validateAuthCode(
        string $clientId,
        string $redirectUri,
        string $authCode
    );

    /**
     * Has access token
     * 
     * Check if an access token exists for a user (or an application)
     * 
     * @access public
     * @return bool|string Return FALSE is a token doesn't exist or return the 
     * access token as a string
     */
    public function hasAccessToken(
        string $typeId,
        string $clientId
    );

    public function getAccessToken(int $sessionId);

    public function removeAuthCode(int $sessionId);

    public function setAccessToken(
        int $sessionId,
        string $accessToken
    );

    public function addSessionScope(
        int $sessionId,
        string $scope
    );

    public function getScope(string $scope);

    public function updateSessionScopeAccessToken(
        int $sesstionId,
        string $accessToken
    );

    public function accessTokenScopes(string $accessToken);
}