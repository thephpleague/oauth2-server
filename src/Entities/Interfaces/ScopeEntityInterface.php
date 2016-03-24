<?php

namespace League\OAuth2\Server\Entities\Interfaces;

interface ScopeEntityInterface extends \JsonSerializable
{
    /**
     * Get the scope's identifier.
     *
     * @return string
     */
    public function getIdentifier();
}
