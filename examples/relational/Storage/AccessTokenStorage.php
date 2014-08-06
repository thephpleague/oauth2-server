<?php

namespace RelationalExample\Storage;

use League\OAuth2\Server\Storage\AccessTokenInterface;
use League\OAuth2\Server\Storage\Adapter;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\AbstractTokenEntity;
use League\OAuth2\Server\Entity\RefreshTokenEntity;
use League\OAuth2\Server\Entity\ScopeEntity;

use Illuminate\Database\Capsule\Manager as Capsule;

class AccessTokenStorage extends Adapter implements AccessTokenInterface
{
    /**
     * {@inheritdoc}
     */
    public function get($token)
    {
        $result = Capsule::table('oauth_access_tokens')
                            ->where('access_token', $token)
                            ->where('expire_time', '>=', time())
                            ->get();

        if (count($result) === 1) {
            $token = (new AccessTokenEntity($this->server))
                        ->setId($result[0]['access_token'])
                        ->setExpireTime($result[0]['expire_time']);

            return $token;
        }

        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes(AbstractTokenEntity $token)
    {
        $result = Capsule::table('oauth_access_token_scopes')
                                    ->select(['oauth_scopes.id', 'oauth_scopes.description'])
                                    ->join('oauth_scopes', 'oauth_access_token_scopes.scope', '=', 'oauth_scopes.id')
                                    ->where('access_token', $token->getId())
                                    ->get();

        $response = [];

        if (count($result) > 0) {
            foreach ($result as $row) {
                $scope = (new ScopeEntity($this->server))->hydrate([
                    'id'            =>  $row['id'],
                    'description'   =>  $row['description']
                ]);
                $response[] = $scope;
            }
        }

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function create($token, $expireTime, $sessionId)
    {
        Capsule::table('oauth_access_tokens')
                    ->insert([
                        'access_token'     =>  $token,
                        'session_id'    =>  $sessionId,
                        'expire_time'   =>  $expireTime
                    ]);
    }

    /**
     * {@inheritdoc}
     */
    public function associateScope(AbstractTokenEntity $token, ScopeEntity $scope)
    {
        Capsule::table('oauth_access_token_scopes')
                    ->insert([
                        'access_token'  =>  $token->getId(),
                        'scope' =>  $scope->getId()
                    ]);
    }

    /**
     * {@inheritdoc}
     */
    public function delete(AbstractTokenEntity $token)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }
}
