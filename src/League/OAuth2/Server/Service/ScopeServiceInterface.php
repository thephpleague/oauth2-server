<?php
/**
 * OAuth 2.0 Scope storage interface
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

/**
 * Interface for any scope service
 */
interface ScopeServiceInterface
{
    /**
     * Return information about a scope
     *
     * @param  string     $scope     The scope
     * @param  string     $clientId  The client ID (default = "null")
     * @param  string     $grantType The grant type used in the request (default = "null")
     * @return bool|array If the scope doesn't exist return false
     */
    public function getScope($scope, $clientId = null, $grantType = null);
}
