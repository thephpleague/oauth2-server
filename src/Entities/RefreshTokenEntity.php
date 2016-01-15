<?php
namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;

/**
 * Class RefreshTokenEntity
 * @package League\OAuth2\Server
 */
class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use EntityTrait, RefreshTokenTrait;
}
