<?php
namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

/**
 * Class RefreshTokenEntity
 * @package League\OAuth2\Server
 */
class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use EntityTrait, TokenEntityTrait, RefreshTokenTrait;
}
