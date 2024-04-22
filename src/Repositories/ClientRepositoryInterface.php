<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;

/**
 * Client storage interface.
 */
interface ClientRepositoryInterface extends RepositoryInterface
{
    /**
     * Get a client.
     */
    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface;

    /**
     * Validate a client's secret.
     */
    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool;
}
