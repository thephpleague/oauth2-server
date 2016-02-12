<?php
/**
 * OAuth 2.0 Auth code storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\Interfaces\AuthCodeEntityInterface;

/**
 * Auth code storage interface
 */
interface AuthCodeRepositoryInterface extends RepositoryInterface
{
    /**
     * Persists a new auth code to permanent storage
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AuthCodeEntityInterface $authCodeEntityInterface
     *
     * @return
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntityInterface);

    /**
     * Revoke an auth code
     *
     * @param string $codeId
     */
    public function revokeAuthCode($codeId);

    /**
     * Check if the auth code has been revoked
     *
     * @param string $codeId
     *
     * @return bool Return true if this code has been revoked
     */
    public function isAuthCodeRevoked($codeId);
}
