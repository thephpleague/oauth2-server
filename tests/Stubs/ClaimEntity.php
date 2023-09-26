<?php


namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\ClaimEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClaimEntityTrait;

class ClaimEntity implements ClaimEntityInterface
{
    use ClaimEntityTrait;

    public function __construct($name, $value)
    {
        $this->name = $name;
        $this->value = $value;
    }
}
