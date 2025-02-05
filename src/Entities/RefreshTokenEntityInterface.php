<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities;

interface RefreshTokenEntityInterface extends TokenInterface
{
    /**
     * Set the access token that the refresh token was associated with.
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken): void;

    /**
     * Get the access token that the refresh token was originally associated with.
     */
    public function getAccessToken(): AccessTokenEntityInterface;
}
