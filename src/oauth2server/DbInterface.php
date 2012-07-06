<?php

interface OAuth2ServerDatabase
{
    public function validateClient(string $clientId, $clientSecret, $redirectUri);

    public function newSession(string $clientId, string $redirectUri, string $type = 'user', string $typeId, $authCode, $accessToken, string $stage = 'request');

    public function updateSession(string $clientId, string $type = 'user', string $typeId, $authCode, $accessToken, string $stage);

    public function deleteSession(string $clientId, string $typeId);

    public function validateAuthCode(string $clientId, string $redirectUri, string $authCode);

    public function getAccessToken(int $sessionId);

    public function removeAuthCode(int $sessionId);

    public function setAccessToken(int $sessionId, string $accessToken);

    public function addSessionScope(int $sessionId, string $scope);

    public function getScope(string $scope);

    public function updateSessionScopeAccessToken(int $sesstionId, string $accessToken);

    public function accessTokenScopes(string $accessToken);

    public function validateUser(string $username, string $password);
}