<?php

namespace RelationalExample\Storage;

use League\OAuth2\Server\Storage\RefreshTokenInterface;
use League\OAuth2\Server\Storage\Adapter;
use League\OAuth2\Server\Entity\RefreshTokenEntity;

use Illuminate\Database\Capsule\Manager as Capsule;

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
        Capsule::table('oauth_refresh_tokens')
                    ->insert([
                        'refresh_token'     =>  $token,
                        'access_token'    =>  $accessToken,
                        'expire_time'   =>  $expireTime
                    ]);
    }

    /**
     * {@inheritdoc}
     */
    public function delete(RefreshTokenEntity $token)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }

}
