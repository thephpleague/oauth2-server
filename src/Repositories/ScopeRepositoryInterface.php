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

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;

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

    /**
     * Given a client and user validate the set of scopes requested are valid and optionally
     * append additional scopes or remove requested scopes.
     *
     * @param ScopeEntityInterface[]                                          $scopes
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface $clientEntity
     * @param null|string                                                     $userIdentifier
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface[]
     */
    public function finalizeScopes(array $scopes = [], ClientEntityInterface $clientEntity, $userIdentifier = null);
}
