<?php

namespace League\OAuth2\Server\Entities\Interfaces;

use Lcobucci\JWT\Builder;

interface AccessTokenEntityInterface extends TokenInterface
{
    /**
     * Generate a JWT from the access token
     *
     * @param string $pathToPrivateKey
     *
     * @return string
     */
    public function convertToJWT($pathToPrivateKey);
}
