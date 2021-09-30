<?php

namespace League\OAuth2\Server\Events;

use Psr\Http\Message\ServerRequestInterface;

final class UserAuthenticationFailed extends AbstractEvent
{
    /** @var string|null */
    private $username;

    public function __construct(
        ?string $username,
        ServerRequestInterface $request
    ) {
        parent::__construct($request);
        $this->name = 'user.authentication.failed';
        $this->username = $username;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }
}
