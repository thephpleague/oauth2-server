<?php

namespace OAuth2ServerExamples\Entities;

use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;

    function jsonSerialize()
    {
        return $this->getIdentifier();
    }
}