<?php
/**
 * @author      Sebastian Kroczek <me@xbug.de>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\ClaimEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;

/**
 * Claim repository interface.
 */
interface ClaimRepositoryInterface extends RepositoryInterface
{
    /**
     * Returns claims
     *
     * @param string                $grantType
     * @param ClientEntityInterface $clientEntity
     * @param string|null           $userIdentifier
     *
     * @return ClaimEntityInterface[]
     */
    public function getClaims(
        string $grantType,
        ClientEntityInterface $clientEntity,
        $userIdentifier = null);
}
