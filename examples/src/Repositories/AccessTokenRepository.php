<?php
namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{

    /**
     * Get an instance of Entity\AccessTokenEntity
     *
     * @param string $tokenIdentifier The access token identifier
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    public function get($tokenIdentifier)
    {
        // TODO: Implement get() method.
    }

    /**
     * Get the scopes for an access token
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $token
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface[]
     */
    public function getScopes(AccessTokenEntityInterface $token)
    {
        // TODO: Implement getScopes() method.
    }

    /**
     * Creates a new access token
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessTokenEntity
     */
    public function create(AccessTokenEntityInterface $accessTokenEntity)
    {
        // TODO: Implement create() method.
    }

    /**
     * Associate a scope with an access token
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessTokenEntityInterface
     * @param \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface       $scope
     */
    public function associateScope(AccessTokenEntityInterface $accessTokenEntityInterface, ScopeEntityInterface $scope)
    {
        // TODO: Implement associateScope() method.
    }

    /**
     * Delete an access token
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessToken
     */
    public function delete(AccessTokenEntityInterface $accessToken)
    {
        // TODO: Implement delete() method.
    }
}
