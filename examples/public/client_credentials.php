<?php

use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Server;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;

include(__DIR__ . '/../vendor/autoload.php');

// Setup the authorization server
$server = new Server();

// Init our repositories
$clientRepository = new ClientRepository();
$scopeRepository = new ScopeRepository();
$accessTokenRepository = new AccessTokenRepository();

// Enable the client credentials grant on the server
$server->enableGrantType(new ClientCredentialsGrant($clientRepository, $scopeRepository, $accessTokenRepository));
