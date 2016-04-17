<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

interface ScopeEntityInterface extends \JsonSerializable
{
    /**
     * Get the scope's identifier.
     *
     * @return string
     */
    public function getIdentifier();
}
