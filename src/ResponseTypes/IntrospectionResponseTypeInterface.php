<?php

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes;

use Psr\Http\Message\ResponseInterface;

interface IntrospectionResponseTypeInterface
{
    public function setActive(bool $active): void;

    public function setTokenType(string $tokenType): void;

    /**
     * @param array<non-empty-string, mixed> $token
     */
    public function setToken(array $token): void;

    public function generateHttpResponse(ResponseInterface $response): ResponseInterface;
}
