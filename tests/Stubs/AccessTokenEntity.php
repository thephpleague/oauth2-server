<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\AbstractJwtAwareAccessToken;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AccessTokenEntity extends AbstractJwtAwareAccessToken
{
    use TokenEntityTrait, EntityTrait;
}
