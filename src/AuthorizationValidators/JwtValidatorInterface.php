<?php

declare(strict_types=1);

namespace League\OAuth2\Server\AuthorizationValidators;

use Psr\Http\Message\ServerRequestInterface;

interface JwtValidatorInterface
{
    /**
     * Parse and validate the given JWT.
     *
     * @param non-empty-string      $jwt
     * @param non-empty-string|null $clientId
     *
     * @return array<non-empty-string, mixed>
     */
    public function validateJwt(ServerRequestInterface $request, string $jwt, ?string $clientId = null): array;
}
