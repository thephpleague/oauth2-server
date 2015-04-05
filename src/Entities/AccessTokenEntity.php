<?php
namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AccessTokenEntity implements AccessTokenEntityInterface
{
    use EntityTrait, TokenEntityTrait;
}
