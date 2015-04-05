<?php
/**
 * OAuth 2.0 Client storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

/**
 * Client storage interface
 */
interface ClientRepositoryInterface extends RepositoryInterface
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
    public function get($clientIdentifier, $clientSecret = null, $redirectUri = null, $grantType = null);
}
