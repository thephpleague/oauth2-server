<?php

namespace LNCD\OAuth2server;

class OAuthSererClientException extends Exception {}

class OAuthServerUserException extends Exception {}

class OAuthServerException extends Exception {}

class Server
{
    protected $errors = array(
        'invalid_request'   =>  'The request is missing a required parameter, includes an invalid parameter value, 
        includes a parameter more than once, or is otherwise malformed.',
        'unauthorized_client'   =>  'The client is not authorized to request an access token using this method.',
        'access_denied' =>  'The resource owner or authorization server denied the request.',
        'unsupported_response_type' =>  'The authorization server does not support obtaining an access token using this 
        method.',
        'invalid_scope' =>  'The requested scope is invalid, unknown, or malformed.',
        'server_error'  =>  'The authorization server encountered an unexpected condition which prevented it from 
        fulfilling the request.',
        'temporarily_unavailable'   =>  'The authorization server is currently unable to handle the request due to a 
        temporary overloading or maintenance of the server.'
    ); 

    public function __construct()
    {
        
    }

    public function registerDbAbstractor()
    {

    }

}