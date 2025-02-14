<?php

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes;

use Psr\Http\Message\ResponseInterface;

class IntrospectionResponse implements IntrospectionResponseTypeInterface
{
    private bool $active = false;

    private ?string $tokenType = null;

    /**
     * @var array<non-empty-string, mixed>
     */
    private ?array $token = null;

    public function setActive(bool $active): void
    {
        $this->active = $active;
    }

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
            if ($this->tokenType === 'access_token') {
                $params = array_merge($params, array_filter([
                    'scope' => $token['scope'] ?? implode(' ', $token['scopes'] ?? []),
                    'client_id' => $token['client_id'] ?? $token['aud'][0] ?? null,
                    'username' => $token['username'] ?? null,
                    'token_type' => 'Bearer',
                    'exp' => $token['exp'] ?? null,
                    'iat' => $token['iat'] ?? null,
                    'nbf' => $token['nbf'] ?? null,
                    'sub' => $token['sub'] ?? null,
                    'aud' => $token['aud'] ?? null,
                    'iss' => $token['iss'] ?? null,
                    'jti' => $token['jti'] ?? null,
                ]));
            } elseif ($this->tokenType === 'refresh_token') {
                $params = array_merge($params, array_filter([
                    'scope' => implode(' ', $token['scopes'] ?? []),
                    'client_id' => $token['client_id'] ?? null,
                    'exp' => $token['expire_time'] ?? null,
                    'sub' => $token['user_id'] ?? null,
                    'jti' => $token['refresh_token_id'] ?? null,
                ]));
            }

            $params = array_merge($params, $this->getExtraParams($this->tokenType, $this->token));
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
     * @param non-empty-string $tokenType
     * @param array<non-empty-string, mixed> $token
     * @return array<non-empty-string, mixed>
     */
    protected function getExtraParams(string $tokenType, array $token): array
    {
        return [];
    }
}
