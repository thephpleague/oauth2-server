<?php

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClaimSetInterface;

/**
 * ClaimSetRepositoryInterface resolve claims for id_token.
 * 
 * @author Marc Riemer <mail@marcriemer.de>
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */
interface ClaimSetRepositoryInterface
{
    /**
     * Get ClaimSetEntries
     *
     * @param AccessTokenEntityInterface $authCode
     * 
     * @return ClaimSetInterface
     */
    public function getClaimSetEntry(AccessTokenEntityInterface $authCode): ClaimSetInterface;
}