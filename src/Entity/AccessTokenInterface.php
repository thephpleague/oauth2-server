<?php
/**
 * OAuth 2.0 Access token entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

/**
 * Access token entity interface
 */
interface AccessTokenInterface extends TokenInterface
{
    /**
     * Get session
     * @return SessionEntity
     */
    public function getSession();

    /**
     * Check if access token has an associated scope
     * @param  string $scope Scope to check
     * @return bool
     */
    public function hasScope($scope);

    /**
     * Return all scopes associated with the access token
     * @return ScopeEntity[]
     */
    public function getScopes();
}
