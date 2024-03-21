<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;

/**
 * Refresh token interface.
 */
interface RefreshTokenRepositoryInterface extends RepositoryInterface
{
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface;

    /**
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void;

    public function revokeRefreshToken(string $tokenId): void;

    public function isRefreshTokenRevoked(string $tokenId): bool;
}
