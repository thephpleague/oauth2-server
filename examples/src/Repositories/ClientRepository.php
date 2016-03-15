<?php

namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use OAuth2ServerExamples\Entities\ClientEntity;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getClientEntity($clientIdentifier, $clientSecret = null, $redirectUri = null, $grantType = null)
    {
        $clients = [
            'myawesomeapp' => [
                'secret'       => password_hash('abc123', PASSWORD_BCRYPT),
                'name'         => 'My Awesome App',
                'redirect_uri' => 'http://foo/bar',
            ],
        ];

        // Check if client is registered
        if (array_key_exists($clientIdentifier, $clients) === false) {
            return null;
        }

        $client = new ClientEntity();
        $client->setIdentifier($clientIdentifier);
        $client->setName($clients[$clientIdentifier]['name']);
        $client->setRedirectUri($clients[$clientIdentifier]['redirect_uri']);
        $client->setSecret($clients[$clientIdentifier]['secret']);

        return $client;
    }
}
