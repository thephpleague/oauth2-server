<?php

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\CryptKey;

interface AccessTokenEntityInterface extends TokenInterface
{
    /**
     * Generate a JWT from the access token
     *
     * @param \League\OAuth2\Server\CryptKey $privateKey
     *
     * @return string
     */
    public function convertToJWT(CryptKey $privateKey);
}
