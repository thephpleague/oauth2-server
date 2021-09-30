<?php

namespace League\OAuth2\Server\Events;

use Psr\Http\Message\ServerRequestInterface;

final class RefreshTokenClientFailed extends AbstractEvent
{
    /** @var string|null */
    private $clientId;

    /** @var array */
    private $refreshTokenData;

    public function __construct(
        ?string $clientId,
        array $refreshTokenData,
        ServerRequestInterface $request
    ) {
        parent::__construct($request);
        $this->name = 'refresh_token.client.failed';
        $this->clientId = $clientId;
        $this->refreshTokenData = $refreshTokenData;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    public function getRefreshTokenData(): array
    {
        return $this->refreshTokenData;
    }
}
