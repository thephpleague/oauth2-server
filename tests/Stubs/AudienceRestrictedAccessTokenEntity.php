<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AudienceRestrictedTokenInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\AudienceRestrictedTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AudienceRestrictedAccessTokenEntity implements AccessTokenEntityInterface, AudienceRestrictedTokenInterface
{
    use AccessTokenTrait;
    use AudienceRestrictedTokenTrait;
    use TokenEntityTrait;
    use EntityTrait;
}
