<?php

declare(strict_types=1);

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use ReturnTypeWillChange;

class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;

    #[ReturnTypeWillChange]
    public function jsonSerialize(): string
    {
        return $this->getIdentifier();
    }
}
