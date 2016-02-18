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
     * @param string      $grantType        The grant type used
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface
     */
    public function getClientEntity($clientIdentifier, $grantType);
}
