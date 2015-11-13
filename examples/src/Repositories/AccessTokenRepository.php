<?php
namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{

    /**
     * @inheritdoc
     */
    public function getAccessTokenEntityByTokenString($tokenIdentifier)
    {
        // TODO: Implement get() method.
    }

    /**
     * @inheritdoc
     */
    public function getScopeEntitiesAssociatedWithAccessToken(AccessTokenEntityInterface $token)
    {
        // TODO: Implement getScopes() method.
    }

    /**
     * @inheritdoc
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        // TODO: Implement create() method.
    }

    /**
     * @inheritdoc
     */
    public function associateScopeWithAccessToken(
        AccessTokenEntityInterface $accessTokenEntityInterface,
        ScopeEntityInterface $scope
    ) {
        // TODO: Implement associateScope() method.
    }

    /**
     * @inheritdoc
     */
    public function deleteAccessToken(AccessTokenEntityInterface $accessToken)
    {
        // TODO: Implement delete() method.
    }
}
