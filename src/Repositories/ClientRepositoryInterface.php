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
     * @param string      $clientIdentifier The client's identifier
     * @param string|null $clientSecret     The client's secret
     * @param string|null $redirectUri      The client's redirect URI
     * @param string|null $grantType        The grant type used
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface
     */
    public function get($clientIdentifier, $clientSecret = null, $redirectUri = null, $grantType = null);
}
