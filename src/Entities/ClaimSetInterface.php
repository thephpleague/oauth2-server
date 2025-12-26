<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Entities;

/**
 * ClaimSetEntryInterface
 *
 * @author Steve Rhoades <sedonami@gmail.com>
 * @author Marc Riemer <mail@marcriemer.de>
 * @license http://opensource.org/licenses/MIT MIT
 */
interface ClaimSetInterface
{
    /**
     * Get Claims
     *
     * @return array<string, string>
     */
    public function getClaims(): array;
}
