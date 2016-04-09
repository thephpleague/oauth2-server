<?php
/**
 * OAuth 2.0 Auth code storage abstract class.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\AuthCodeEntity;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;

/**
 * Auth code storage abstract class.
 */
abstract class AbstractAuthCodeRepository implements AuthCodeRepositoryInterface
{
    /**
     * Creates a new AuthCode
     *
     * @return \League\OAuth2\Server\Entities\AuthCodeEntityInterface
     */
    public function getNewAuthCode()
    {
        return new AuthCodeEntity();
    }

    /**
     * Persists a new auth code to permanent storage.
     *
     * @param \League\OAuth2\Server\Entities\AuthCodeEntityInterface $authCodeEntity
     */
    abstract public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity);

    /**
     * Revoke an auth code.
     *
     * @param string $codeId
     */
    abstract public function revokeAuthCode($codeId);

    /**
     * Check if the auth code has been revoked.
     *
     * @param string $codeId
     *
     * @return bool Return true if this code has been revoked
     */
    abstract public function isAuthCodeRevoked($codeId);
}
