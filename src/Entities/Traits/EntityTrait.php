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

trait EntityTrait
{
    /**
     * @var non-empty-string
     */
    protected string $identifier;

    /**
     * @return non-empty-string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @param non-empty-string $identifier
     */
    public function setIdentifier(string $identifier): void
    {
        $this->identifier = $identifier;
    }
}
