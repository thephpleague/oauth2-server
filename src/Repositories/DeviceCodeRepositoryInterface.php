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

use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;

interface DeviceCodeRepositoryInterface extends RepositoryInterface
{
    /**
     * Creates a new DeviceCode
     */
    public function getNewDeviceCode(): DeviceCodeEntityInterface;

    /**
     * Persists a device code to permanent storage.
     *
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persistDeviceCode(DeviceCodeEntityInterface $deviceCodeEntity): void;

    /**
     * Persists user ID and approval status of the given device code entity to permanent storage.
     */
    public function persistUser(DeviceCodeEntityInterface $deviceCodeEntity): void;

    /**
     * Persists "last polled at" datetime of the given device code entity to permanent storage.
     */
    public function persistLastPolledAt(DeviceCodeEntityInterface $deviceCodeEntity): void;

    /**
     * Get a device code entity.
     */
    public function getDeviceCodeEntityByDeviceCode(
        string $deviceCodeEntity
    ): ?DeviceCodeEntityInterface;

    /**
     * Revoke a device code.
     */
    public function revokeDeviceCode(string $codeId): void;

    /**
     * Check if the device code has been revoked.
     *
     * @return bool Return true if this code has been revoked
     */
    public function isDeviceCodeRevoked(string $codeId): bool;
}
