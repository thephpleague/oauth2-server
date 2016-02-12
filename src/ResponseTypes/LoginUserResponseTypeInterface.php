<?php

namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;

interface LoginUserResponseTypeInterface
{
    /**
     * Return a login form
     *
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface $client
     * @param ScopeEntityInterface[]                                          $scopes
     * @param string                                                          $queryString
     * @param string                                                          $pathToPrivateKey
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function handle(ClientEntityInterface $client, array $scopes, $queryString, $pathToPrivateKey);
}