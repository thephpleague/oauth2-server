<?php

namespace League\OAuth2\Server\Repositories;

use Lcobucci\JWT\Builder;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

/**
 * IdTokenRepositoryInterface
 *
 * @author Marc Riemer <mail@marcriemer.de>
 * @license http://opensource.org/licenses/MIT MIT
 */
interface IdTokenRepositoryInterface
{
    /**
     * Creates new token builder and may add some standard claims
     *
     * @param AccessTokenEntityInterface $token Issued access token
     *
     * @return Builder
     */
    public function getBuilder(AccessTokenEntityInterface $token): Builder;
}
