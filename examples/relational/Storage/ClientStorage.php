<?php

namespace RelationalExample\Storage;

use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\Adapter;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\SessionEntity;

use Illuminate\Database\Capsule\Manager as Capsule;

class ClientStorage extends Adapter implements ClientInterface
{
    /**
     * {@inheritdoc}
     */
    public function get($clientId, $clientSecret = null, $redirectUri = null, $grantType = null)
    {
        die(var_dump(__METHOD__, func_get_args()));
    }

    /**
     * {@inheritdoc}
     */
    public function getBySession(SessionEntity $session)
    {
        $result = Capsule::table('oauth_clients')
                            ->select(['oauth_clients.id', 'oauth_clients.name'])
                            ->join('oauth_sessions', 'oauth_clients.id', '=', 'oauth_sessions.client_id')
                            ->where('oauth_sessions.id', $session->getId())
                            ->get();

        if (count($result) === 1) {
            $client = new ClientEntity($this->server);
            $client->setId($result[0]['id']);
            $client->setName($result[0]['name']);

            return $client;
        }
    }
}
