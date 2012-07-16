<?php

namespace oauth2server;

interface DatabaseInteface
{
    public function validateClient(
        $clientId,
        $clientSecret,
        $redirectUri
    );

    public function newSession(
        $clientId,
        $redirectUri,
        $type = 'user',
        $typeId = null,
        $authCode = null,
        $accessToken = null,
        $stage = 'request'
    );

    public function updateSession(
        $clientId,
        $type = 'user',
        $typeId = null,
        $authCode = null,
        $accessToken = null,
        $stage
    );

    public function deleteSession(
        $clientId,
        $type,
        $typeId
    );

    public function validateAuthCode(
        $clientId,
        $redirectUri,
        $authCode
    );

    /**
     * Has access token
     * 
     * Check if an access token exists for a user (or an application)
     * 
     * @access public
     * @return bool|Return FALSE is a token doesn't exist or return the 
     * access token as a string
     */
    public function hasAccessToken(
        $typeId,
        $clientId
    );

    public function getAccessToken($sessionId);

    public function removeAuthCode($sessionId);

    public function setAccessToken(
        $sessionId,
        $accessToken
    );

    public function addSessionScope(
        $sessionId,
        $scope
    );

    public function getScope($scope);

    public function updateSessionScopeAccessToken(
        $sesstionId,
        $accessToken
    );

    public function accessTokenScopes($accessToken);
}