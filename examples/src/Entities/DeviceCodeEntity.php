<?php
/**
 * @author Andrew Millington <andrew@noexceptions.io>
 * @copyright Copyright (c) Alex Bilbie
 * @license http://mit-license.org/
 *
 * @link https://github.com/thephpleague/oauth2-server
 */

namespace OAuth2ServerExamples\Entities;

use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\DeviceCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class DeviceCodeEntity implements DeviceCodeEntityInterface
{
    use EntityTrait, DeviceCodeTrait, TokenEntityTrait;
}
