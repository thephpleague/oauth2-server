<?php
/**
 * OAuth 2.0 Client entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

/**
 * Hydratable entity interface
 */
interface HydratableInterface
{
    /**
     * Hydrate an entity with properties
     * @param  array $properties
     * @return self
     */
    public function hydrate(array $properties);
}
