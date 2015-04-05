<?php
/**
 * OAuth 2.0 Scope storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

/**
 * Scope interface
 */
interface ScopeRepositoryInterface extends RepositoryInterface
{
    /**
     * Return information about a scope
     *
     * @param string $scopeIdentifier The scope identifier
     * @param string $grantType       The grant type used in the request (default = "null")
     * @param string $clientId        The client sending the request (default = "null")
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface
     */
    public function get($scopeIdentifier, $grantType = null, $clientId = null);
}
