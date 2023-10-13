<?php

/**
 * @author    Andrew Millington <andrew@noexceptions.io>
 * @copyright Copyright (c) Andrew Millington
 * @license   http://mit-license.org
 *
 * @link      https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities\Traits;

trait ScopeTrait
{
    /**
     * Serialize the object to the scopes string identifier when using json_encode().
     */
    public function jsonSerialize(): string
    {
        return $this->getIdentifier();
    }

    abstract public function getIdentifier(): string;
}
