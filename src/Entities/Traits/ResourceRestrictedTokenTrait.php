<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities\Traits;

/**
 * Default in-memory implementation of {@see \League\OAuth2\Server\Entities\ResourceRestrictedTokenInterface}.
 */
trait ResourceRestrictedTokenTrait
{
    /**
     * @var list<non-empty-string>
     */
    private array $resources = [];

    /**
     * @return list<non-empty-string>
     */
    public function getResources(): array
    {
        return $this->resources;
    }

    /**
     * @param list<non-empty-string> $resources
     */
    public function setResources(array $resources): void
    {
        $this->resources = $resources;
    }
}
