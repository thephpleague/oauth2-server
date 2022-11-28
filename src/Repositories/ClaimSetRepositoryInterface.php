<?php

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClaimSetInterface;
use Psr\Http\Message\ServerRequestInterface;

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
     * Access AccessTokenEntityInterface and ServerRequestInterface returned by the resource server after successfull authorization
     *
     * @param AccessTokenEntityInterface|ServerRequestInterface $resource
     *
     * @return ClaimSetInterface
     */
    public function getClaimSetEntry(AccessTokenEntityInterface|ServerRequestInterface $resource): ClaimSetInterface;
}
