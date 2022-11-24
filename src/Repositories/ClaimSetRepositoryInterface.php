<?php

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\ClaimSetEntryInterface;

/**
 * ClaimSetRepositoryInterface helps to resolve claims for id_token
 * 
 * @author Marc Riemer <mail@marcriemer.de>
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */
interface ClaimSetRepositoryInterface
{
    public function getClaimSetByUserIdentifier($userIdentifyer): ClaimSetEntryInterface;
}