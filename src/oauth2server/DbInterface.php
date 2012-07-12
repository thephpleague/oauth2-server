<?php
/*
Copyright (C) 2012 University of Lincoln

Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in 
the Software without restriction, including without limitation the rights to 
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace oauth2server;

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