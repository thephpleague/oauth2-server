<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\DeviceCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class DeviceCodeEntity implements DeviceCodeEntityInterface
{
    use EntityTrait, TokenEntityTrait, DeviceCodeTrait;
}
