<?php

namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\Interfaces\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{

    /**
     * Persists a new auth code to permanent storage
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AuthCodeEntityInterface $authCodeEntity
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity)
    {
        // TODO: Implement persistNewAuthCode() method.
    }

    /**
     * Revoke an auth code
     *
     * @param string $codeId
     */
    public function revokeAuthCode($codeId)
    {
        // TODO: Implement revokeAuthCode() method.
    }

    /**
     * Check if the auth code has been revoked
     *
     * @param string $codeId
     *
     * @return bool Return true if this code has been revoked
     */
    public function isAuthCodeRevoked($codeId)
    {
        // TODO: Implement isAuthCodeRevoked() method.
    }
}