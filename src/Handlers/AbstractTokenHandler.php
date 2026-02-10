<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Handlers;

use League\OAuth2\Server\AbstractHandler;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidatorInterface;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

abstract class AbstractTokenHandler extends AbstractHandler implements TokenHandlerInterface
{
    private CryptKeyInterface $publicKey;

    private ?BearerTokenValidatorInterface $bearerTokenValidator = null;

    public function setPublicKey(CryptKeyInterface $publicKey): void
    {
        $this->publicKey = $publicKey;
    }

    public function setBearerTokenValidator(BearerTokenValidatorInterface $bearerTokenValidator): void
    {
        $this->bearerTokenValidator = $bearerTokenValidator;
    }

    protected function getBearerTokenValidator(): BearerTokenValidatorInterface
    {
        if ($this->bearerTokenValidator instanceof BearerTokenValidatorInterface === false) {
            $this->bearerTokenValidator = new BearerTokenValidator($this->accessTokenRepository);
        }

        if ($this->bearerTokenValidator instanceof BearerTokenValidator === true) {
            $this->bearerTokenValidator->setPublicKey($this->publicKey);
        }

        return $this->bearerTokenValidator;
    }

    /**
     * @return array{type: non-empty-string, data: array<non-empty-string, mixed>}|null
     *
     * @throws OAuthServerException
     */
    protected function validateToken(
        ServerRequestInterface $request,
        ClientEntityInterface $client
    ): ?array {
        $token = $this->getRequestParameter('token', $request)
            ?? throw OAuthServerException::invalidRequest('token');

        $tokenTypeHint = $this->getRequestParameter('token_type_hint', $request, 'access_token');

        // If the token cannot be located using the provided token type hint, we extend
        // the search across all supported token types according to the RFC spec.
        if ($tokenTypeHint === 'refresh_token') {
            return $this->validateRefreshToken($request, $token, $client)
                ?? $this->validateAccessToken($request, $token, $client);
        }

        return $this->validateAccessToken($request, $token, $client)
            ?? $this->validateRefreshToken($request, $token, $client);
    }

    /**
     * @return array{type: non-empty-string, data: array<non-empty-string, mixed>}|null
     */
    private function validateRefreshToken(
        ServerRequestInterface $request,
        string $refreshToken,
        ClientEntityInterface $client
    ): ?array {
        try {
            return [
                'type' => 'refresh_token',
                'data' => $this->validateEncryptedRefreshToken($request, $refreshToken, $client->getIdentifier()),
            ];
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @param non-empty-string $accessToken
     *
     * @return array{type: non-empty-string, data: array<non-empty-string, mixed>}|null
     */
    private function validateAccessToken(
        ServerRequestInterface $request,
        string $accessToken,
        ClientEntityInterface $client
    ): ?array {
        try {
            return [
                'type' => 'access_token',
                'data' => $this->getBearerTokenValidator()->validateBearerToken(
                    $request,
                    $accessToken,
                    $client->getIdentifier()
                ),
            ];
        } catch (Throwable) {
            return null;
        }
    }
}
