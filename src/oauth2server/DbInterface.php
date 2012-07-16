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