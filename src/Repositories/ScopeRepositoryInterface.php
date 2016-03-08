<?php
/**
 * OAuth 2.0 Scope storage interface.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Repositories;

/**
 * Scope interface.
 */
interface ScopeRepositoryInterface extends RepositoryInterface
{
    /**
     * Return information about a scope.
     *
     * @param string      $identifier The scope identifier
     * @param string      $grantType  The grant type used in the request
     * @param string|null $clientId   The client sending the request
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface
     */
    public function getScopeEntityByIdentifier($identifier, $grantType, $clientId = null);
}
