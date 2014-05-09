<?php

namespace RelationalExample\Storage;

use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\Adapter;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\ScopeEntity;

use Illuminate\Database\Capsule\Manager as Capsule;

class SessionStorage extends Adapter implements SessionInterface
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
    public function getByAccessToken(AccessTokenEntity $accessToken)
    {
        $result = Capsule::table('oauth_sessions')
                            ->select(['oauth_sessions.id', 'oauth_sessions.owner_type', 'oauth_sessions.owner_id', 'oauth_sessions.client_id', 'oauth_sessions.client_redirect_uri'])
                            ->join('oauth_access_tokens', 'oauth_access_tokens.session_id', '=', 'oauth_sessions.id')
                            ->where('oauth_access_tokens.access_token', $accessToken->getToken())
                            ->get();

        if (count($result) === 1) {
            // die(var_dump($result));
            $session = new SessionEntity($this->server);
            $session->setId($result[0]['id']);
            $session->setOwner($result[0]['owner_type'], $result[0]['owner_id']);

            return $session;
        }

        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getByAuthCode(AuthCodeEntity $authCode)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes(SessionEntity $session)
    {
        die(var_dump(__CLASS__.'::'.__METHOD__, func_get_args()));
    }

    /**
     * {@inheritdoc}
     */
    public function create($ownerType, $ownerId, $clientId, $clientRedirectUri = null)
    {
        die(var_dump(__CLASS__.'::'.__METHOD__, func_get_args()));
    }

    /**
     * {@inheritdoc}
     */
    public function associateScope(SessionEntity $session, ScopeEntity $scope)
    {
        die(var_dump(__CLASS__.'::'.__METHOD__, func_get_args()));
    }
}
