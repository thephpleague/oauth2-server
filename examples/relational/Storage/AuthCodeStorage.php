<?php

namespace RelationalExample\Storage;

use League\OAuth2\Server\Storage\AuthCodeInterface;
use League\OAuth2\Server\Storage\Adapter;

class AuthCodeStorage extends Adapter implements AuthCodeInterface
{
    /**
     * {@inheritdoc}
     */
    public function get($token)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }
}
