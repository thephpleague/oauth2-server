<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\AbstractJwtAwareRefreshToken;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class RefreshTokenEntity extends AbstractJwtAwareRefreshToken
{
    use EntityTrait;
}
