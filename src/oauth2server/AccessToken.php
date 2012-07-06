<?php

namespace LNCD\OAuth2server;

class AccessToken
{
    function __construct()
    {

    }

    public function get(int $sessionId)
    {
        // returns an access token that the user may already have (else generate a new one)
    }

    public function validate(string $accessToken, array $scopes)
    {
        // tests if an access token is valid
    }

    private function set(int $sessionId)
    {
        // generate a new access token
    }
}