<?php

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes;

use DateTimeInterface;
use Psr\Http\Message\ResponseInterface;

class IntrospectionResponse implements IntrospectionResponseTypeInterface
{
    protected bool $active = false;

    /**
     * @var non-empty-string|null
     */
    protected ?string $tokenType = null;

    /**
     * @var array<non-empty-string, mixed>
     */
    protected ?array $token = null;

    public function setActive(bool $active): void
    {
        $this->active = $active;
    }

    /**
     * {@inheritdoc}
     */
    public function setTokenType(string $tokenType): void
    {
        $this->tokenType = $tokenType;
    }

    /**
     * {@inheritdoc}
     */
    public function setToken(array $token): void
    {
        $this->token = $token;
    }

    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        $params = [
            'active' => $this->active,
        ];

        if ($this->active === true && $this->tokenType !== null && $this->token !== null) {
            $params = array_merge(
                $params,
                $this->parseParams($this->tokenType, $this->token),
                $this->getExtraParams($this->tokenType, $this->token)
            );
        }

        $params = json_encode($params, flags: JSON_THROW_ON_ERROR);

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write($params);

        return $response;
    }

    /**
     * @param non-empty-string               $tokenType
     * @param array<non-empty-string, mixed> $token
     *
     * @return array<non-empty-string, mixed>
     */
    protected function parseParams(string $tokenType, array $token): array
    {
        if ($tokenType === 'access_token') {
            return array_filter([
                'scope' => $token['scope'] ?? implode(' ', $token['scopes'] ?? []),
                'client_id' => $token['client_id'] ?? $token['aud'][0] ?? null,
                'username' => $token['username'] ?? null,
                'token_type' => 'Bearer',
                'exp' => isset($token['exp']) ? $this->convertTimestamp($token['exp']) : null,
                'iat' => isset($token['iat']) ? $this->convertTimestamp($token['iat']) : null,
                'nbf' => isset($token['nbf']) ? $this->convertTimestamp($token['nbf']) : null,
                'sub' => $token['sub'] ?? null,
                'aud' => $token['aud'] ?? null,
                'iss' => $token['iss'] ?? null,
                'jti' => $token['jti'] ?? null,
            ], fn ($value) => !is_null($value));
        } elseif ($tokenType === 'refresh_token') {
            return array_filter([
                'scope' => implode(' ', $token['scopes'] ?? []),
                'client_id' => $token['client_id'] ?? null,
                'exp' => isset($token['expire_time']) ? $this->convertTimestamp($token['expire_time']) : null,
                'sub' => $token['user_id'] ?? null,
                'jti' => $token['refresh_token_id'] ?? null,
            ], fn ($value) => !is_null($value));
        } else {
            return [];
        }
    }

    protected function convertTimestamp(int|float|string|DateTimeInterface $value): int
    {
        return match (true) {
            $value instanceof DateTimeInterface => $value->getTimestamp(),
            default => intval($value),
        };
    }

    /**
     * @param non-empty-string               $tokenType
     * @param array<non-empty-string, mixed> $token
     *
     * @return array<non-empty-string, mixed>
     */
    protected function getExtraParams(string $tokenType, array $token): array
    {
        return [];
    }
}
