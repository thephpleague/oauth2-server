<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities;

use DateTimeImmutable;

interface DeviceCodeEntityInterface extends TokenInterface
{
    public function getUserCode(): string;

    public function setUserCode(string $userCode): void;

    public function getVerificationUri(): string;

    public function setVerificationUri(string $verificationUri): void;

    public function getVerificationUriComplete(): string;

    public function getLastPolledAt(): ?DateTimeImmutable;

    public function setLastPolledAt(DateTimeImmutable $lastPolledAt): void;

    public function getInterval(): int;

    public function setInterval(int $interval): void;

    public function getUserApproved(): bool;

    public function setUserApproved(bool $userApproved): void;
}
