<?php

declare(strict_types=1);

namespace League\OAuth2\Server\AuthorizationValidators;

use Psr\Http\Message\ServerRequestInterface;

interface BearerTokenValidatorInterface
{
    /**
     * Parse and validate the given bearer token.
     *
     * @param non-empty-string      $token
     * @param non-empty-string|null $clientId
     *
     * @return array<non-empty-string, mixed>
     */
    public function validateBearerToken(ServerRequestInterface $request, string $token, ?string $clientId = null): array;
}
