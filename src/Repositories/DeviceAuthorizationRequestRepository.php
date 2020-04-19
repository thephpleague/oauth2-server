<?php
/**
 * @author    Andrew Millington <andrew@noexceptions.io>
 * @copyright Copyright (c) Alex Bilbie
 * @license   http://mit-license.org/
 *
 * @link      https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

use DateTimeImmutable;

/**
 * Device authorization request storage interface.
 */
interface DeviceAuthorizationRequestRepository extends RepositoryInterface
{
    /**
     * @param string $deviceCode
     *
     * @return DateTimeImmutable;
     */
    public function getLast($deviceCode);

    /**
     * @param string $deviceCode
     */
    public function persist($deviceCode);
}
