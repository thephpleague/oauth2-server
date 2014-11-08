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
        $result = Capsule::table('oauth_refresh_tokens')
                            ->where('refresh_token', $token)
                            ->get();

        if (count($result) === 1) {
            $token = (new RefreshTokenEntity($this->server))
                        ->setId($result[0]['refresh_token'])
                        ->setExpireTime($result[0]['expire_time'])
                        ->setAccessTokenId($result[0]['access_token']);

            return $token;
        }

        return null;
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
        Capsule::table('oauth_refresh_tokens')
                            ->where('refresh_token', $token->getId())
                            ->delete();
    }

}
