<?php

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientEntityTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * Class ClientEntity.
 */
class ClientEntity implements ClientEntityInterface
{
    use EntityTrait, ClientEntityTrait;
}
