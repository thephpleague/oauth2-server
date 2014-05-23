<?php

namespace RelationalExample\Storage;

use League\OAuth2\Server\Storage\RefreshTokenInterface;
use League\OAuth2\Server\Storage\Adapter;
use League\OAuth2\Server\Entity\RefreshTokenEntity;

class RefreshTokenStorage extends Adapter implements RefreshTokenInterface
{
    /**
     * {@inheritdoc}
     */
    public function get($token)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }

    /**
     * {@inheritdoc}
     */
    public function create($token, $expireTime, $accessToken)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }

    /**
     * {@inheritdoc}
     */
    public function delete(RefreshTokenEntity $token)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }

}
