<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use OAuth2ServerExamples\Entities\ClientEntity;

use function array_key_exists;
use function password_hash;
use function password_verify;

class ClientRepository implements ClientRepositoryInterface
{
    private const CLIENT_NAME = 'My Awesome App';
    private const REDIRECT_URI = 'http://foo/bar';

    /**
     * {@inheritdoc}
     */
    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $client = new ClientEntity();

        $client->setIdentifier($clientIdentifier);
        $client->setName(self::CLIENT_NAME);
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType): bool
    {
        $clients = [
            'myawesomeapp' => [
                'secret'          => password_hash('abc123', PASSWORD_BCRYPT),
                'name'            => self::CLIENT_NAME,
                'redirect_uri'    => self::REDIRECT_URI,
                'is_confidential' => true,
            ],
        ];

        // Check if client is registered
        if (array_key_exists($clientIdentifier, $clients) === false) {
            return false;
        }

        if (password_verify($clientSecret, $clients[$clientIdentifier]['secret']) === false) {
            return false;
        }

        return true;
    }
}
