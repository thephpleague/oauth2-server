<?php

namespace RelationalExample\Storage;

use League\OAuth2\Server\Storage\AuthCodeInterface;
use League\OAuth2\Server\Storage\Adapter;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\Entity\ScopeEntity;

use Illuminate\Database\Capsule\Manager as Capsule;

class AuthCodeStorage extends Adapter implements AuthCodeInterface
{
    /**
     * {@inheritdoc}
     */
    public function get($code)
    {
        $result = Capsule::table('oauth_auth_codes')
                            ->where('auth_code', $code)
                            ->where('expire_time', '>=', time())
                            ->get();

        if (count($result) === 1) {
            $token = new AuthCodeEntity($this->server);
            $token->setId($result[0]['auth_code']);
            return $token;
        }

        return null;
    }

    public function create($token, $$expireTime, $sessionId)
    {
        Capsule::table('oauth_auth_codes')
                    ->insert([
                        'auth_code'     =>  $token,
                        'client_redirect_uri'  =>  $redirectUri,
                        'session_id'    =>  $sessionId,
                        'expire_time'   =>  $expireTime
                    ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes(AuthCodeEntity $token)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }

    /**
     * {@inheritdoc}
     */
    public function associateScope(AuthCodeEntity $token, ScopeEntity $scope)
    {
        Capsule::table('oauth_auth_code_scopes')
                            ->insert([
                                'auth_code' =>  $token->getToken(),
                                'scope'     =>  $scope->getId()
                            ]);
    }

    /**
     * {@inheritdoc}
     */
    public function delete(AuthCodeEntity $token)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }
}
