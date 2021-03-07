<?php

namespace League\OAuth2\Server\Events;

use Psr\Http\Message\ServerRequestInterface;

final class ClientAuthenticationFailed extends AbstractEvent
{
    /** @var string|null */
    private $clientId;

    public function __construct(
        ?string $clientId,
        ServerRequestInterface $request
    ) {
        parent::__construct($request);
        $this->name = 'client.authentication.failed';
        $this->clientId = $clientId;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }
}
