<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;

class RequestAccessTokenAudiencesEvent extends RequestEvent
{
    private bool $requestDenied = false;

    private ?string $denyReason = null;

    /**
     * @param list<non-empty-string> $audiences
     */
    public function __construct(
        string $name,
        ServerRequestInterface $request,
        #[SensitiveParameter]
        private AccessTokenEntityInterface $accessToken,
        private array $audiences
    ) {
        parent::__construct($name, $request);
    }

    /**
     * @codeCoverageIgnore
     */
    public function getAccessToken(): AccessTokenEntityInterface
    {
        return $this->accessToken;
    }

    /**
     * @return list<non-empty-string>
     */
    public function getAudiences(): array
    {
        return $this->audiences;
    }

    /**
     * @param list<non-empty-string> $audiences
     */
    public function setAudiences(array $audiences): void
    {
        $this->audiences = $audiences;
    }

    public function denyRequest(?string $reason = null): void
    {
        $this->requestDenied = true;
        $this->denyReason = $reason;
    }

    public function isRequestDenied(): bool
    {
        return $this->requestDenied;
    }

    public function getDenyReason(): ?string
    {
        return $this->denyReason;
    }
}
