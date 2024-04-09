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
     * @var int|non-empty-string
     */
    protected int|string $identifier;

    /**
     * @return non-empty-string
     */
    public function getIdentifier(): int|string
    {
        return $this->identifier;
    }

    /**
     * @param int|non-empty-string $identifier
     */
    public function setIdentifier(int|string $identifier): void
    {
        $this->identifier = $identifier;
    }
}
