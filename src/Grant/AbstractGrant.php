<?php

/**
 * OAuth 2.0 Abstract grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Grant;

use DateInterval;
use DateTimeImmutable;
use DomainException;
use Error;
use Exception;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\EventEmitting\EmitterAwarePolyfill;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\RedirectUriValidators\RedirectUriValidator;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\DeviceCodeResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use TypeError;

use function array_filter;
use function array_key_exists;
use function base64_decode;
use function bin2hex;
use function explode;
use function is_null;
use function is_string;
use function random_bytes;
use function strpos;
use function substr;
use function trim;

/**
 * Abstract grant class.
 */
abstract class AbstractGrant implements GrantTypeInterface
{
    use EmitterAwarePolyfill;
    use CryptTrait;

    protected const SCOPE_DELIMITER_STRING = ' ';

    protected const MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS = 10;

    protected ClientRepositoryInterface $clientRepository;

    protected AccessTokenRepositoryInterface $accessTokenRepository;

    protected ScopeRepositoryInterface $scopeRepository;

    protected AuthCodeRepositoryInterface $authCodeRepository;

    protected RefreshTokenRepositoryInterface $refreshTokenRepository;

    protected UserRepositoryInterface $userRepository;

    protected DateInterval $refreshTokenTTL;

    protected CryptKeyInterface $privateKey;

    protected string $defaultScope;

    protected bool $revokeRefreshTokens = true;

    public function setClientRepository(ClientRepositoryInterface $clientRepository): void
    {
        $this->clientRepository = $clientRepository;
    }

    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository): void
    {
        $this->accessTokenRepository = $accessTokenRepository;
    }

    public function setScopeRepository(ScopeRepositoryInterface $scopeRepository): void
    {
        $this->scopeRepository = $scopeRepository;
    }

    public function setRefreshTokenRepository(RefreshTokenRepositoryInterface $refreshTokenRepository): void
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    public function setAuthCodeRepository(AuthCodeRepositoryInterface $authCodeRepository): void
    {
        $this->authCodeRepository = $authCodeRepository;
    }

    public function setUserRepository(UserRepositoryInterface $userRepository): void
    {
        $this->userRepository = $userRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function setRefreshTokenTTL(DateInterval $refreshTokenTTL): void
    {
        $this->refreshTokenTTL = $refreshTokenTTL;
    }

    /**
     * Set the private key
     */
    public function setPrivateKey(CryptKeyInterface $key): void
    {
        $this->privateKey = $key;
    }

    public function setDefaultScope(string $scope): void
    {
        $this->defaultScope = $scope;
    }

    public function revokeRefreshTokens(bool $revokeRefreshTokens): void
    {
        $this->revokeRefreshTokens = $revokeRefreshTokens;
    }

    /**
     * Validate the client.
     *
     * @throws OAuthServerException
     */
    protected function validateClient(ServerRequestInterface $request): ClientEntityInterface
    {
        [$clientId, $clientSecret] = $this->getClientCredentials($request);

        if ($this->clientRepository->validateClient($clientId, $clientSecret, $this->getIdentifier()) === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidClient($request);
        }

        $client = $this->getClientEntityOrFail($clientId, $request);

        // If a redirect URI is provided ensure it matches what is pre-registered
        $redirectUri = $this->getRequestParameter('redirect_uri', $request, null);

        if ($redirectUri !== null) {
            if (!is_string($redirectUri)) {
                throw OAuthServerException::invalidRequest('redirect_uri');
            }

            $this->validateRedirectUri($redirectUri, $client, $request);
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
     * @return string[]
     */
    protected function getClientCredentials(ServerRequestInterface $request): array
    {
        [$basicAuthUser, $basicAuthPassword] = $this->getBasicAuthCredentials($request);

        $clientId = $this->getRequestParameter('client_id', $request, $basicAuthUser);

        if (is_null($clientId)) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        $clientSecret = $this->getRequestParameter('client_secret', $request, $basicAuthPassword);

        if ($clientSecret !== null && !is_string($clientSecret)) {
            throw OAuthServerException::invalidRequest('client_secret');
        }

        return [$clientId, $clientSecret];
    }

    /**
     * Validate redirectUri from the request. If a redirect URI is provided
     * ensure it matches what is pre-registered
     *
     * @throws OAuthServerException
     */
    protected function validateRedirectUri(
        string $redirectUri,
        ClientEntityInterface $client,
        ServerRequestInterface $request
    ): void {
        $validator = new RedirectUriValidator($client->getRedirectUri());

        if (!$validator->validateRedirectUri($redirectUri)) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient($request);
        }
    }

    /**
     * Validate scopes in the request.
     *
     * @param null|string|string[] $scopes
     *
     * @throws OAuthServerException
     *
     * @return ScopeEntityInterface[]
     */
    public function validateScopes(string|array|null $scopes, string $redirectUri = null): array
    {
        if ($scopes === null) {
            $scopes = [];
        } elseif (is_string($scopes)) {
            $scopes = $this->convertScopesQueryStringToArray($scopes);
        }

        $validScopes = [];

        foreach ($scopes as $scopeItem) {
            $scope = $this->scopeRepository->getScopeEntityByIdentifier($scopeItem);

            if ($scope instanceof ScopeEntityInterface === false) {
                throw OAuthServerException::invalidScope($scopeItem, $redirectUri);
            }

            $validScopes[] = $scope;
        }

        return $validScopes;
    }

    /**
     * Converts a scopes query string to an array to easily iterate for validation.
     *
     * @return string[]
     */
    private function convertScopesQueryStringToArray(string $scopes): array
    {
        return array_filter(explode(self::SCOPE_DELIMITER_STRING, trim($scopes)), function ($scope) {
            return $scope !== '';
        });
    }

    /**
     * Retrieve request parameter.
     */
    protected function getRequestParameter(string $parameter, ServerRequestInterface $request, mixed $default = null): mixed
    {
        $requestParameters = (array) $request->getParsedBody();

        return $requestParameters[$parameter] ?? $default;
    }

    /**
     * Retrieve HTTP Basic Auth credentials with the Authorization header
     * of a request. First index of the returned array is the username,
     * second is the password (so list() will work). If the header does
     * not exist, or is otherwise an invalid HTTP Basic header, return
     * [null, null].
     *
     * @return string[]|null[]
     */
    protected function getBasicAuthCredentials(ServerRequestInterface $request): array
    {
        if (!$request->hasHeader('Authorization')) {
            return [null, null];
        }

        $header = $request->getHeader('Authorization')[0];
        if (strpos($header, 'Basic ') !== 0) {
            return [null, null];
        }

        $decoded = base64_decode(substr($header, 6), true);

        if ($decoded === false) {
            return [null, null];
        }

        if (strpos($decoded, ':') === false) {
            return [null, null]; // HTTP Basic header without colon isn't valid
        }

        return explode(':', $decoded, 2);
    }

    /**
     * Retrieve query string parameter.
     */
    protected function getQueryStringParameter(string $parameter, ServerRequestInterface $request, mixed $default = null): ?string
    {
        return isset($request->getQueryParams()[$parameter]) ? $request->getQueryParams()[$parameter] : $default;
    }

    /**
     * Retrieve cookie parameter.
     */
    protected function getCookieParameter(string $parameter, ServerRequestInterface $request, mixed $default = null): ?string
    {
        return isset($request->getCookieParams()[$parameter]) ? $request->getCookieParams()[$parameter] : $default;
    }

    /**
     * Retrieve server parameter.
     */
    protected function getServerParameter(string $parameter, ServerRequestInterface $request, mixed $default = null): ?string
    {
        return isset($request->getServerParams()[$parameter]) ? $request->getServerParams()[$parameter] : $default;
    }

    /**
     * Issue an access token.
     *
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     *
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        string|int|null $userIdentifier,
        array $scopes = []
    ): AccessTokenEntityInterface {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $accessToken = $this->accessTokenRepository->getNewToken($client, $scopes, $userIdentifier);
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add($accessTokenTTL));
        $accessToken->setPrivateKey($this->privateKey);

        while ($maxGenerationAttempts-- > 0) {
            $accessToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->accessTokenRepository->persistNewAccessToken($accessToken);

                return $accessToken;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }

        // This should never be hit. It is here to work around a PHPStan false error
        return $accessToken;
    }

    /**
     * Issue an auth code.
     *
     * @param non-empty-string $userIdentifier
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueAuthCode(
        DateInterval $authCodeTTL,
        ClientEntityInterface $client,
        string $userIdentifier,
        ?string $redirectUri,
        array $scopes = []
    ): AuthCodeEntityInterface {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $authCode = $this->authCodeRepository->getNewAuthCode();
        $authCode->setExpiryDateTime((new DateTimeImmutable())->add($authCodeTTL));
        $authCode->setClient($client);
        $authCode->setUserIdentifier($userIdentifier);

        if ($redirectUri !== null) {
            $authCode->setRedirectUri($redirectUri);
        }

        foreach ($scopes as $scope) {
            $authCode->addScope($scope);
        }

        while ($maxGenerationAttempts-- > 0) {
            $authCode->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->authCodeRepository->persistNewAuthCode($authCode);

                return $authCode;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }

        // This should never be hit. It is here to work around a PHPStan false error
        return $authCode;
    }

    /**
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        $refreshToken = $this->refreshTokenRepository->getNewRefreshToken();

        if ($refreshToken === null) {
            return null;
        }

        $refreshToken->setExpiryDateTime((new DateTimeImmutable())->add($this->refreshTokenTTL));
        $refreshToken->setAccessToken($accessToken);

        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        while ($maxGenerationAttempts-- > 0) {
            $refreshToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);

                return $refreshToken;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }

        // This should never be hit. It is here to work around a PHPStan false error
        return $refreshToken;
    }

    /**
     * Generate a new unique identifier.
     *
     * @throws OAuthServerException
     */
    protected function generateUniqueIdentifier(int $length = 40): string
    {
        try {
            if ($length < 1) {
                throw new DomainException('Length must be a positive integer');
            }

            return bin2hex(random_bytes($length));
            // @codeCoverageIgnoreStart
        } catch (TypeError | Error $e) {
            throw OAuthServerException::serverError('An unexpected error has occurred', $e);
        } catch (Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            throw OAuthServerException::serverError('Could not generate a random string', $e);
        }
        // @codeCoverageIgnoreEnd
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAccessTokenRequest(ServerRequestInterface $request): bool
    {
        $requestParameters = (array) $request->getParsedBody();

        return (
            array_key_exists('grant_type', $requestParameters)
            && $requestParameters['grant_type'] === $this->getIdentifier()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        throw new LogicException('This grant cannot validate an authorization request');
    }

    /**
     * {@inheritdoc}
     */
    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        throw new LogicException('This grant cannot complete an authorization request');
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToDeviceAuthorizationRequest(ServerRequestInterface $request): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function respondToDeviceAuthorizationRequest(ServerRequestInterface $request): DeviceCodeResponse
    {
        throw new LogicException('This grant cannot validate a device authorization request');
    }

    /**
     * {@inheritdoc}
     */
    public function completeDeviceAuthorizationRequest(string $deviceCode, string $userId, bool $userApproved): void
    {
        throw new LogicException('This grant cannot complete a device authorization request');
    }
}
