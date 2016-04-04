<?php

namespace League\OAuth2\Server\Jwt;

use Lcobucci\JWT\Builder;
use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;

interface AccessTokenConverterInterface
{
    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     *
     * @return Builder
     */
    public function convert(AccessTokenEntityInterface $accessTokenEntity);
}
