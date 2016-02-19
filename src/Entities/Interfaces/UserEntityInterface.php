<?php

namespace League\OAuth2\Server\Entities\Interfaces;

interface UserEntityInterface
{
    /**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier();
}
