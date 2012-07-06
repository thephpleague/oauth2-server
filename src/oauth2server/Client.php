<?php

namespace LNCD\OAuth2server;

class Client
{
    protected $id;
    protected $secret;
    protected $redirect_uri;

    public function __construct()
    {

    }

    public function validate(array $details)
    {

    }

    public function redirectUri(string $redirectUri, array $params, $queryDelimeter = '?')
    {
        // Generates the redirect uri with appended params
    }
}