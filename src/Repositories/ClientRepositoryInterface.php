<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Repositories;

/**
 * Client storage interface.
 */
interface ClientRepositoryInterface extends RepositoryInterface
{
    /**
     * Get a client.
     *
     * @param string      $clientIdentifier   The client's identifier
     * @param string      $grantType          The grant type used
     * @param null|string $clientSecret       The client's secret (if sent)
     * @param bool        $mustValidateSecret If true the client must attempt to validate the secret unless the client
     *                                        is confidential
     *
     * @return \League\OAuth2\Server\Entities\ClientEntityInterface
     */
    public function getClientEntity($clientIdentifier, $grantType, $clientSecret = null, $mustValidateSecret = true);
}
