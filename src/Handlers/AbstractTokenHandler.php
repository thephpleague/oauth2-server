<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Handlers;

use League\OAuth2\Server\AbstractHandler;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\AuthorizationValidators\JwtValidatorInterface;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

abstract class AbstractTokenHandler extends AbstractHandler implements TokenHandlerInterface
{
    private CryptKeyInterface $publicKey;

    private ?JwtValidatorInterface $jwtValidator = null;

    public function setPublicKey(CryptKeyInterface $publicKey): void
    {
        $this->publicKey = $publicKey;
    }

    public function setJwtValidator(JwtValidatorInterface $jwtValidator): void
    {
        $this->jwtValidator = $jwtValidator;
    }

    protected function getJwtValidator(): JwtValidatorInterface
    {
        if ($this->jwtValidator instanceof JwtValidatorInterface === false) {
            $this->jwtValidator = new BearerTokenValidator($this->accessTokenRepository);
        }

        if ($this->jwtValidator instanceof BearerTokenValidator === true) {
            $this->jwtValidator->setPublicKey($this->publicKey);
        }

        return $this->jwtValidator;
    }

    /**
     * @return array{0:non-empty-string, 1:array<non-empty-string, mixed>}|array{0:null, 1:null}
     *
     * @throws OAuthServerException
     */
    protected function validateToken(
        ServerRequestInterface $request,
        ClientEntityInterface $client
    ): array {
        $token = $this->getRequestParameter('token', $request)
            ?? throw OAuthServerException::invalidRequest('token');

        $tokenTypeHint = $this->getRequestParameter('token_type_hint', $request, 'access_token');

        if ($tokenTypeHint === 'refresh_token') {
            return $this->validateRefreshToken($request, $token, $client)
                ?? $this->validateAccessToken($request, $token, $client)
                ?? [null, null];
        }

        return $this->validateAccessToken($request, $token, $client)
            ?? $this->validateRefreshToken($request, $token, $client)
            ?? [null, null];
    }

    /**
     * @return array{0:non-empty-string, 1:array<non-empty-string, mixed>}|null
     */
    protected function validateRefreshToken(
        ServerRequestInterface $request,
        string $refreshToken,
        ClientEntityInterface $client
    ): ?array {
        try {
            return [
                'refresh_token',
                $this->validateEncryptedRefreshToken($request, $refreshToken, $client->getIdentifier()),
            ];
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @param non-empty-string $accessToken
     *
     * @return array{0:non-empty-string, 1:array<non-empty-string, mixed>}|null
     */
    protected function validateAccessToken(
        ServerRequestInterface $request,
        string $accessToken,
        ClientEntityInterface $client
    ): ?array {
        try {
            return [
                'access_token',
                $this->getJwtValidator()->validateJwt($request, $accessToken, $client->getIdentifier()),
            ];
        } catch (Throwable) {
            return null;
        }
    }
}
