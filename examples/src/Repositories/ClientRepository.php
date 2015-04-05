<?php
namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\ClientEntity;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * Get a client
     *
     * @param string $clientIdentifier The client's identifier
     * @param string $clientSecret     The client's secret (default = "null")
     * @param string $redirectUri      The client's redirect URI (default = "null")
     * @param string $grantType        The grant type used (default = "null")
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface
     */
    public function get($clientIdentifier, $clientSecret = null, $redirectUri = null, $grantType = null)
    {
        $clients = [
            'myawesomeapp' => [
                'secret'       => password_hash('abc123', PASSWORD_BCRYPT),
                'name'         => 'My Awesome App',
                'redirect_uri' => ''
            ]
        ];

        // Check if client is registered
        if (array_key_exists($clientIdentifier, $clients) === false) {
            return null;
        }

        // Check if client secret is valid
        if ($clientSecret !== null && password_verify($clientSecret, $clients[$clientIdentifier]['secret']) === false) {
            return null;
        }

        // Check if redirect URI is valid
        if ($redirectUri !== null && $redirectUri !== $clients[$clientIdentifier]['redirectUri']) {
            return null;
        }

        $client = new ClientEntity();
        $client->setIdentifier($clientIdentifier);
        $client->setName($clients[$clientIdentifier]['name']);

        return $client;
    }
}
