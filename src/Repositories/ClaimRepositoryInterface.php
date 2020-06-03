<?php
/**
 * @author      Sebastian Kroczek <me@xbug.de>
 * @copyright   Copyright (c) Sebastian Kroczek
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\ClaimEntityInterface;

/**
 * Claim repository interface.
 */
interface ClaimRepositoryInterface extends RepositoryInterface
{
    /**
     * Returns claims
     *
     *
     * @return ClaimEntityInterface[]
     */
    public function getClaims();
}
