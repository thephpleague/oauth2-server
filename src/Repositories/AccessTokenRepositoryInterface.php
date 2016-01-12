<?php
/**
 * OAuth 2.0 Access token storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;

/**
 * Access token interface
 */
interface AccessTokenRepositoryInterface extends RepositoryInterface
{
    /**
     * Get an instance of Entity\AccessTokenEntity
     *
     * @param string $token The access token identifier
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    public function getAccessTokenEntityByTokenString($token);

    /**
     * Get the scopes for an access token
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $token
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface[]
     */
    public function getScopeEntitiesAssociatedWithAccessToken(AccessTokenEntityInterface $token);

    /**
     * Persists a new access token to permanent storage
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessTokenEntity
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity);

    /**
     * Associate a scope with an access token
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessTokenEntityInterface
     * @param \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface       $scope
     */
    public function associateScopeWithAccessToken(
        AccessTokenEntityInterface $accessTokenEntityInterface,
        ScopeEntityInterface $scope
    );

    /**
     * Delete an access token
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessToken
     */
    public function deleteAccessToken(AccessTokenEntityInterface $accessToken);
}
