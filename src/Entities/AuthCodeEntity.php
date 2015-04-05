<?php
namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Entities\Interfaces\AuthCodeInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

/**
 * Class AuthCodeEntity
 * @package League\OAuth2\Server
 */
class AuthCodeEntity implements AuthCodeInterface
{
    use EntityTrait, TokenEntityTrait;
}
