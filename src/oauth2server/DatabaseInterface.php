<?php

namespace oauth2server;

interface DatabaseInteface
{
    /**
     * [validateClient description]
     * @param  string $clientId     The client's ID
     * @param  string $clientSecret The client's secret (default = "null")
     * @param  string $redirectUri  The client's redirect URI (default = "null")
     * @return [type]               [description]
     */
    public function validateClient(
        $clientId,
        $clientSecret = null,
        $redirectUri = null
    );

    /**
     * [newSession description]
     * @param  string $clientId    The client ID
     * @param  string $redirectUri The redirect URI
     * @param  string $type        The session owner's type (default = "user")
     * @param  string $typeId      The session owner's ID (default = "null")
     * @param  string $authCode    The authorisation code (default = "null")
     * @param  string $accessToken The access token (default = "null")
     * @param  string $stage       The stage of the session (default ="request")
     * @return [type]              [description]
     */
    public function newSession(
        $clientId,
        $redirectUri,
        $type = 'user',
        $typeId = null,
        $authCode = null,
        $accessToken = null,
        $stage = 'request'
    );

    /**
     * [updateSession description]
     * @param  string $clientId    The client ID
     * @param  string $type        The session owner's type (default = "user")
     * @param  string $typeId      The session owner's ID (default = "null")
     * @param  string $authCode    The authorisation code (default = "null")
     * @param  string $accessToken The access token (default = "null")
     * @param  string $stage       The stage of the session (default ="request")
     * @return [type]              [description]
     */
    public function updateSession(
        $clientId,
        $type = 'user',
        $typeId = null,
        $authCode = null,
        $accessToken = null,
        $stage
    );

    /**
     * [deleteSession description]
     * @param  string $clientId The client ID
     * @param  string $type     The session owner's type 
     * @param  string $typeId   The session owner's ID
     * @return [type]           [description]
     */
    public function deleteSession(
        $clientId,
        $type,
        $typeId
    );

    /**
     * [validateAuthCode description]
     * @param  string $clientId    The client ID
     * @param  string $redirectUri The redirect URI
     * @param  string $authCode    The authorisation code
     * @return [type]              [description]
     */
    public function validateAuthCode(
        $clientId,
        $redirectUri,
        $authCode
    );

    /**
     * [hasAccessToken description]
     * @param  string  $type     The session owner's type 
     * @param  string  $typeId   The session owner's ID
     * @param  string  $clientId The client ID
     * @return boolean           [description]
     */
    public function hasAccessToken(
        $type,
        $typeId,
        $clientId
    );

    /**
     * [getAccessToken description]
     * @param  int    $sessionId The OAuth session ID
     * @return [type]            [description]
     */
    public function getAccessToken($sessionId);

    /**
     * [removeAuthCode description]
     * @param  int    $sessionId The OAuth session ID
     * @return [type]            [description]
     */
    public function removeAuthCode($sessionId);

    /**
     * [setAccessToken description]
     * @param int    $sessionId   The OAuth session ID
     * @param string $accessToken The access token
     */
    public function setAccessToken(
        int $sessionId,
        $accessToken
    );

    /**
     * [addSessionScope description]
     * @param int    $sessionId [description]
     * @param string $scope     [description]
     */
    public function addSessionScope(
        $sessionId,
        $scope
    );

    /**
     * [getScope description]
     * @param  string $scope [description]
     * @return [type]        [description]
     */
    public function getScope($scope);

    /**
     * [updateSessionScopeAccessToken description]
     * @param  int    $sesstionId  [description]
     * @param  string $accessToken [description]
     * @return [type]              [description]
     */
    public function updateSessionScopeAccessToken(
        $sesstionId,
        $accessToken
    );

    /**
     * [accessTokenScopes description]
     * @param  string $accessToken [description]
     * @return [type]              [description]
     */
    public function accessTokenScopes($accessToken);
}