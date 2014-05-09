<?php

namespace RelationalExample\Storage;

use League\OAuth2\Server\Storage\ScopeInterface;
use League\OAuth2\Server\Storage\Adapter;

class ScopeStorage extends Adapter implements ScopeInterface
{
    /**
     * {@inheritdoc}
     */
    public function get($scope, $grantType = null)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }
}
