<?php

namespace League\OAuth2\Server\Entities;

/**
 * ClaimSetEntry
 * 
 * @author Steve Rhoades <sedonami@gmail.com>
 * @author Marc Riemer <mail@marcriemer.de>
 * @license http://opensource.org/licenses/MIT MIT
 */
class ClaimSetEntry implements ClaimSetEntryInterface
{
    public function __construct(
        protected string $scope, 
        protected array $claims)
    {}

    /**
     * Get scope
     *
     * @return string
     */
    public function getScope(): string
    {
        return $this->scope;
    }

    /**
     * Get claims
     *
     * @return ClaimSetInterface[]
     */
    public function getClaims(): array
    {
        return $this->claims;
    }
}
