<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

use DateTimeImmutable;

interface RefreshTokenEntityInterface
{
    /**
     * Get the token's identifier.
     *
     * @return string
     */
    public function getIdentifier();

    /**
     * Set the token's identifier.
     */
    public function setIdentifier(mixed $identifier): void;

    /**
     * Get the token's expiry date time.
     */
    public function getExpiryDateTime(): DateTimeImmutable;

    /**
     * Set the date time when the token expires.
     */
    public function setExpiryDateTime(DateTimeImmutable $dateTime): void;

    /**
     * Set the access token that the refresh token was associated with.
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken): void;

    /**
     * Get the access token that the refresh token was originally associated with.
     */
    public function getAccessToken(): AccessTokenEntityInterface;
}
