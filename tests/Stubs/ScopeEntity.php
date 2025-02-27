<?php

declare(strict_types=1);

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;
use ReturnTypeWillChange;

class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;
    use ScopeTrait;

    #[ReturnTypeWillChange]
    public function jsonSerialize(): string
    {
        return $this->getIdentifier();
    }
}
