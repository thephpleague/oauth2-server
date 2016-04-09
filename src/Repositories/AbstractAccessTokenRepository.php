<?php
namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntity;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;

abstract class AbstractAccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * Create a new access token
     *
     * @param \League\OAuth2\Server\Entities\ClientEntityInterface  $clientEntity
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     * @param mixed                                                 $userIdentifier
     *
     * @return \League\OAuth2\Server\Entities\AccessTokenEntityInterface
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        return new AccessTokenEntity();
    }

    /**
     * Persists a new access token to permanent storage.
     *
     * @param \League\OAuth2\Server\Entities\AccessTokenEntityInterface $accessTokenEntity
     */
    abstract public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity);

    /**
     * Revoke an access token.
     *
     * @param string $tokenId
     */
    abstract public function revokeAccessToken($tokenId);

    /**
     * Check if the access token has been revoked.
     *
     * @param string $tokenId
     *
     * @return bool Return true if this token has been revoked
     */
    abstract public function isAccessTokenRevoked($tokenId);
}
