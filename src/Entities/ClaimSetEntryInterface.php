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
interface ClaimSetEntryInterface extends ClaimSetInterface
{
    public function getScope(): string;
}
