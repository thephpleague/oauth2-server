<?php

namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;

interface AccessTokenConverterInterface
{
    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     *
     * @return string
     */
    public function convert(AccessTokenEntityInterface $accessTokenEntity);
}
