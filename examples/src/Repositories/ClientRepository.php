<?php

namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\ClientEntity;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

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
            return;
        }

        // Check if client secret is valid
        if ($clientSecret !== null && password_verify($clientSecret, $clients[$clientIdentifier]['secret']) === false) {
            return;
        }

        // Check if redirect URI is valid
        if ($redirectUri !== null && $redirectUri !== $clients[$clientIdentifier]['redirect_uri']) {
            return;
        }

        $client = new ClientEntity();
        $client->setIdentifier($clientIdentifier);
        $client->setName($clients[$clientIdentifier]['name']);

        return $client;
    }
}
