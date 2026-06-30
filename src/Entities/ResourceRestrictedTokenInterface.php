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

/**
 * Opt-in extension for token entities that carry RFC 8707 resource
 * restrictions.
 *
 * Implementing this interface is optional: {@see TokenInterface} remains the
 * canonical contract and existing consumer implementations continue to work
 * without modification. Grants check for this interface via `instanceof` when
 * propagating resource indicators through the token flow.
 */
interface ResourceRestrictedTokenInterface
{
    /**
     * @return list<non-empty-string> The absolute URIs of the resources this token is bound to.
     */
    public function getResources(): array;

    /**
     * @param list<non-empty-string> $resources
     */
    public function setResources(array $resources): void;
}
