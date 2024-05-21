<?php

/**
 * @author      Andrew Millington <andrew@noexceptions.io>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities\Traits;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

trait DeviceCodeTrait
{
    private bool $userApproved = false;
    private bool $includeVerificationUriComplete = false;
    private int $interval = 5;
    private string $userCode;
    private string $verificationUri;
    private ?DateTimeImmutable $lastPolledAt = null;

    public function getUserCode(): string
    {
        return $this->userCode;
    }

    public function setUserCode(string $userCode): void
    {
        $this->userCode = $userCode;
    }

    public function getVerificationUri(): string
    {
        return $this->verificationUri;
    }

    public function setVerificationUri(string $verificationUri): void
    {
        $this->verificationUri = $verificationUri;
    }

    public function getVerificationUriComplete(): string
    {
        return $this->verificationUri . '?user_code=' . $this->userCode;
    }

    abstract public function getClient(): ClientEntityInterface;

    abstract public function getExpiryDateTime(): DateTimeImmutable;

    /**
     * @return ScopeEntityInterface[]
     */
    abstract public function getScopes(): array;

    /**
     * @return non-empty-string
     */
    abstract public function getIdentifier(): string;

    public function getLastPolledAt(): ?DateTimeImmutable
    {
        return $this->lastPolledAt;
    }

    public function setLastPolledAt(DateTimeImmutable $lastPolledAt): void
    {
        $this->lastPolledAt = $lastPolledAt;
    }

    public function getInterval(): int
    {
        return $this->interval;
    }

    public function setInterval(int $interval): void
    {
        $this->interval = $interval;
    }

    public function getUserApproved(): bool
    {
        return $this->userApproved;
    }

    public function setUserApproved(bool $userApproved): void
    {
        $this->userApproved = $userApproved;
    }

    public function getVerificationUriCompleteInAuthResponse(): bool
    {
        return $this->includeVerificationUriComplete;
    }

    public function setVerificationUriCompleteInAuthResponse(bool $includeVerificationUriComplete): void
    {
        $this->includeVerificationUriComplete = $includeVerificationUriComplete;
    }
}
