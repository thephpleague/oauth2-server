<?php

namespace RelationalExample\Storage;

use Illuminate\Database\Capsule\Manager as Capsule;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Storage\AbstractStorage;
use League\OAuth2\Server\Storage\AccessTokenInterface;

class AccessTokenStorage extends AbstractStorage implements AccessTokenInterface
{
    /**
     * {@inheritdoc}
     */
    public function get($token)
    {
        $result = Capsule::table('oauth_access_tokens')
                            ->where('access_token', $token)
                            ->get();

        if (count($result) === 1) {
            $token = (new AccessTokenEntity($this->server))
                        ->setId($result[0]['access_token'])
                        ->setExpireTime($result[0]['expire_time']);

            return $token;
        }

        return;
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes(AccessTokenEntity $token)
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
                    'description'   =>  $row['description'],
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
                        'expire_time'   =>  $expireTime,
                    ]);
    }

    /**
     * {@inheritdoc}
     */
    public function associateScope(AccessTokenEntity $token, ScopeEntity $scope)
    {
        Capsule::table('oauth_access_token_scopes')
                    ->insert([
                        'access_token'  =>  $token->getId(),
                        'scope' =>  $scope->getId(),
                    ]);
    }

    /**
     * {@inheritdoc}
     */
    public function delete(AccessTokenEntity $token)
    {
        Capsule::table('oauth_access_tokens')
                    ->where('access_token', $token->getId())
                    ->delete();
    }
}
