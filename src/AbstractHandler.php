<?php

declare(strict_types=1);

namespace League\OAuth2\Server;

use Exception;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\EventEmitting\EmitterAwareInterface;
use League\OAuth2\Server\EventEmitting\EmitterAwarePolyfill;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

use function base64_decode;
use function explode;
use function json_decode;
use function substr;
use function time;
use function trim;

abstract class AbstractHandler implements EmitterAwareInterface
{
    use EmitterAwarePolyfill;
    use CryptTrait;

    protected ClientRepositoryInterface $clientRepository;

    protected AccessTokenRepositoryInterface $accessTokenRepository;

    protected RefreshTokenRepositoryInterface $refreshTokenRepository;

    public function setClientRepository(ClientRepositoryInterface $clientRepository): void
    {
        $this->clientRepository = $clientRepository;
    }

    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository): void
    {
        $this->accessTokenRepository = $accessTokenRepository;
    }

    public function setRefreshTokenRepository(RefreshTokenRepositoryInterface $refreshTokenRepository): void
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    /**
     * Validate the client.
     *
     * @throws OAuthServerException
     */
    protected function validateClient(ServerRequestInterface $request): ClientEntityInterface
    {
        [$clientId, $clientSecret] = $this->getClientCredentials($request);

        $client = $this->getClientEntityOrFail($clientId, $request);

        if ($client->isConfidential()) {
            if ($clientSecret === '') {
                throw OAuthServerException::invalidRequest('client_secret');
            }

            if (
                $this->clientRepository->validateClient(
                    $clientId,
                    $clientSecret,
                    $this instanceof GrantTypeInterface ? $this->getIdentifier() : null
                ) === false
            ) {
                $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));

                throw OAuthServerException::invalidClient($request);
            }
        }

        return $client;
    }

    /**
     * Wrapper around ClientRepository::getClientEntity() that ensures we emit
     * an event and throw an exception if the repo doesn't return a client
     * entity.
     *
     * This is a bit of defensive coding because the interface contract
     * doesn't actually enforce non-null returns/exception-on-no-client so
     * getClientEntity might return null. By contrast, this method will
     * always either return a ClientEntityInterface or throw.
     *
     * @throws OAuthServerException
     */
    protected function getClientEntityOrFail(string $clientId, ServerRequestInterface $request): ClientEntityInterface
    {
        $client = $this->clientRepository->getClientEntity($clientId);

        if ($client instanceof ClientEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient($request);
        }

        return $client;
    }

    /**
     * Gets the client credentials from the request from the request body or
     * the Http Basic Authorization header
     *
     * @return array{0:non-empty-string,1:string}
     *
     * @throws OAuthServerException
     */
    protected function getClientCredentials(ServerRequestInterface $request): array
    {
        [$basicAuthUser, $basicAuthPassword] = $this->getBasicAuthCredentials($request);

        $clientId = $this->getRequestParameter('client_id', $request, $basicAuthUser);

        if ($clientId === null) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        $clientSecret = $this->getRequestParameter('client_secret', $request, $basicAuthPassword);

        return [$clientId, $clientSecret ?? ''];
    }
    /**
     * Parse request parameter.
     *
     * @param array<array-key, mixed> $request
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    private static function parseParam(string $parameter, array $request, ?string $default = null): ?string
    {
        $value = $request[$parameter] ?? '';

        if (is_scalar($value)) {
            $value = trim((string) $value);
        } else {
            throw OAuthServerException::invalidRequest($parameter);
        }

        if ($value === '') {
            $value = $default === null ? null : trim($default);

            if ($value === '') {
                $value = null;
            }
        }

        return $value;
    }

    /**
     * Retrieve request parameter.
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    protected function getRequestParameter(string $parameter, ServerRequestInterface $request, ?string $default = null): ?string
    {
        return self::parseParam($parameter, (array) $request->getParsedBody(), $default);
    }

    /**
     * Retrieve HTTP Basic Auth credentials with the Authorization header
     * of a request. First index of the returned array is the username,
     * second is the password (so list() will work). If the header does
     * not exist, or is otherwise an invalid HTTP Basic header, return
     * [null, null].
     *
     * @return array{0:non-empty-string,1:string}|array{0:null,1:null}
     */
    protected function getBasicAuthCredentials(ServerRequestInterface $request): array
    {
        if (!$request->hasHeader('Authorization')) {
            return [null, null];
        }

        $header = $request->getHeader('Authorization')[0];
        if (stripos($header, 'Basic ') !== 0) {
            return [null, null];
        }

        $decoded = base64_decode(substr($header, 6), true);

        if ($decoded === false) {
            return [null, null];
        }

        if (str_contains($decoded, ':') === false) {
            return [null, null]; // HTTP Basic header without colon isn't valid
        }

        [$username, $password] = explode(':', $decoded, 2);

        if ($username === '') {
            return [null, null];
        }

        return [$username, $password];
    }

    /**
     * Retrieve query string parameter.
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    protected function getQueryStringParameter(string $parameter, ServerRequestInterface $request, ?string $default = null): ?string
    {
        return self::parseParam($parameter, $request->getQueryParams(), $default);
    }

    /**
     * Retrieve cookie parameter.
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    protected function getCookieParameter(string $parameter, ServerRequestInterface $request, ?string $default = null): ?string
    {
        return self::parseParam($parameter, $request->getCookieParams(), $default);
    }

    /**
     * Retrieve server parameter.
     *
     * @return non-empty-string|null
     *
     * @throws OAuthServerException
     */
    protected function getServerParameter(string $parameter, ServerRequestInterface $request, ?string $default = null): ?string
    {
        return self::parseParam($parameter, $request->getServerParams(), $default);
    }

    /**
     * Validate the given encrypted refresh token.
     *
     * @throws OAuthServerException
     *
     * @return array<string, mixed>
     */
    protected function validateEncryptedRefreshToken(
        ServerRequestInterface $request,
        string $encryptedRefreshToken,
        string $clientId
    ): array {
        try {
            $refreshToken = $this->decrypt($encryptedRefreshToken);
        } catch (Exception $e) {
            throw OAuthServerException::invalidRefreshToken('Cannot decrypt the refresh token', $e);
        }

        $refreshTokenData = json_decode($refreshToken, true);

        if ($refreshTokenData['client_id'] !== $clientId) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
            throw OAuthServerException::invalidRefreshToken('Token is not linked to client');
        }

        if ($refreshTokenData['expire_time'] < time()) {
            throw OAuthServerException::invalidRefreshToken('Token has expired');
        }

        if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshTokenData['refresh_token_id']) === true) {
            throw OAuthServerException::invalidRefreshToken('Token has been revoked');
        }

        return $refreshTokenData;
    }
}
