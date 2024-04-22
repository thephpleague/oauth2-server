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

use JsonSerializable;

interface ScopeEntityInterface extends JsonSerializable
{
    /**
     * Get the scope's identifier.
     *
     * @return non-empty-string
     */
    public function getIdentifier(): string;
}
