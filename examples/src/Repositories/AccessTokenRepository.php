<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use OAuth2ServerExamples\Entities\AccessTokenEntity;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        // Some logic here to save the access token to a database
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken($tokenId): void
    {
        // Some logic here to revoke the access token
    }

    /**
     * {@inheritdoc}
     */
    public function isAccessTokenRevoked($tokenId): bool
    {
        return false; // Access token hasn't been revoked
    }

    /**
     * {@inheritdoc}
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?UserEntityInterface $user = null): AccessTokenEntityInterface
    {
        $accessToken = new AccessTokenEntity();

        $accessToken->setClient($clientEntity);
        $accessToken->setUser($user);

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        return $accessToken;
    }
}
