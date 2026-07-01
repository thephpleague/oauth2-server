<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\RequestTypes;

/**
 * Opt-in extension of {@see AuthorizationRequestInterface} for implementations
 * that carry RFC 8707 resource indicators through the authorization flow.
 *
 * Implementing this interface is optional; grants that support RFC 8707 check
 * for it via `instanceof` so existing consumer implementations of the base
 * {@see AuthorizationRequestInterface} remain backwards compatible.
 */
interface ResourceIndicatorAwareInterface
{
    /**
     * @return list<non-empty-string> The absolute URIs of the requested resources.
     */
    public function getResources(): array;

    /**
     * @param list<non-empty-string> $resources
     */
    public function setResources(array $resources): void;
}
