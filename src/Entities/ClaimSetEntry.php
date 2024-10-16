<?php

declare(strict_types=1);

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
    /**
     * Summary of __construct
     *
     * @param string   $scope  Scope of the claimset
     * @param string[] $claims The claims
     */
    public function __construct(
        protected string $scope,
        protected array $claims
    ) {
    }

    /**
     * Get scope
     */
    public function getScope(): string
    {
        return $this->scope;
    }

    /**
     * Get claims
     *
     * @return string[]
     */
    public function getClaims(): array
    {
        return $this->claims;
    }
}
