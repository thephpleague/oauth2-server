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
}
