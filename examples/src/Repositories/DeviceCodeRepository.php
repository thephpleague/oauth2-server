<?php
/**
 * @author    Andrew Millington <andrew@noexceptions.io>
 * @copyright Copyright (c) Alex Bilbie
 * @license   http://mit-license.org/
 *
 * @link      https://github.com/thephpleague/oauth2-server
 */

namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use League\OAuth2\Server\Repositories\DeviceCodeRepositoryInterface;
use OAuth2ServerExamples\Entities\ClientEntity;
use OAuth2ServerExamples\Entities\DeviceCodeEntity;

use DateTimeImmutable;

class DeviceCodeRepository implements DeviceCodeRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getNewDeviceCode(): DeviceCodeEntityInterface
    {
        return new DeviceCodeEntity();
    }

    /**
     * {@inheritdoc}
     */
    public function persistDeviceCode(DeviceCodeEntityInterface $deviceCodeEntity): void
    {
        // Some logic to persist a new device code to a database
    }

    /**
     * {@inheritdoc}
     */
    public function getDeviceCodeEntityByDeviceCode($deviceCode): ?DeviceCodeEntityInterface
    {
        $clientEntity = new ClientEntity();
        $clientEntity->setIdentifier('myawesomeapp');

        $deviceCodeEntity = new DeviceCodeEntity();

        $deviceCodeEntity->setIdentifier($deviceCode);
        $deviceCodeEntity->setExpiryDateTime((new DateTimeImmutable)->setTimestamp($this->getDeviceCodeExpiryTime($deviceCode)));
        $deviceCodeEntity->setClient($clientEntity);

        // TODO: Check if this is still true as it seems we need to set userapproved
        // The user identifier should be set when the user authenticates on the OAuth server
        $deviceCodeEntity->setUserApproved(true);
        $deviceCodeEntity->setUserIdentifier(1);

        return $deviceCodeEntity;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeDeviceCode($codeId): void
    {
        // Some logic to revoke device code
    }

    /**
     * {@inheritdoc}
     */
    public function isDeviceCodeRevoked($codeId): bool
    {
        return false;
    }
    
    // TODO: This should probably return a datetimeimmutable object to match the setter
    public function getDeviceCodeExpiryTime(string $codeId): int
    {
        return (new DateTimeImmutable('now + 1 hour'))->getTimestamp();
    }

    public function getDeviceCodeClientId(string $codeId): string
    {
        // Some logic to get the client ID of the device code
    }
}
