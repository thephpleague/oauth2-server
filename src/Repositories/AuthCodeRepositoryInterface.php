<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;

/**
 * Auth code storage interface.
 */
interface AuthCodeRepositoryInterface extends RepositoryInterface
{
    public function getNewAuthCode(): AuthCodeEntityInterface;

    /**
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void;

    public function revokeAuthCode(string $codeId): void;

    public function isAuthCodeRevoked(string $codeId): bool;

    /**
     * Method locks an auth code in case an error occurs during the issuance of an access code.
     *
     * The storage engine should make this persistent immediately to prevent possible race conditions while issuing an access token.
     *
     * @param string $codeId
     */
    public function lockAuthCode(string $codeId): bool;

    /**
     * This method is used to make the auth code available again after an error occurred in the access code issuance process.
     *
     * @param string $codeId
     */
    public function unlockAuthCode(string $codeId): void;

    public function isAuthCodeLocked(string $codeId): bool;
}
