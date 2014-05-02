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

namespace League\OAuth2\Server\Storage;

/**
 * Scope interface
 */
interface ScopeInterface
{
    /**
     * Return information about a scope
     *
     * Example SQL query:
     *
     * <code>
     * SELECT * FROM oauth_scopes WHERE scope = :scope
     * </code>
     *
     * @param  string     $scope     The scope
     * @param  string     $grantType The grant type used in the request (default = "null")
     * @return \League\OAuth2\Server\Entity\ScopeEntity
     */
    public function get($scope, $grantType = null);
}
