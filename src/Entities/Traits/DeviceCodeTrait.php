<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities\Traits;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

trait DeviceCodeTrait
{
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

    public function setVerificationUri(string $verificationUri)
    {
        $this->verificationUri = $verificationUri;
    }

    abstract public function getClient(): ClientEntityInterface;

    abstract public function getExpiryDateTime(): DateTimeImmutable;

    /**
     * @return ScopeEntityInterface[]
     */
    abstract public function getScopes(): array;

    abstract public function getIdentifier(): string;

    public function getLastPolledAt(): ?DateTimeImmutable
    {
        return $this->lastPolledAt;
    }

    public function setLastPolledAt(DateTimeImmutable $lastPolledAt): void
    {
        $this->lastPolledAt = $lastPolledAt;
    }
}
