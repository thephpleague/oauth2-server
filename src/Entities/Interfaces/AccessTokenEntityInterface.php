<?php

namespace League\OAuth2\Server\Entities\Interfaces;

interface AccessTokenEntityInterface extends TokenInterface
{
    /**
     * Generate a JWT from the access token
     *
     * @param string $privateKeyPath
     *
     * @return string
     */
    public function convertToJWT($privateKeyPath);
}
