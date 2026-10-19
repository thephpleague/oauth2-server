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
use League\OAuth2\Server\Entities\AudienceRestrictedTokenInterface;
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
use League\Uri\Exceptions\SyntaxError;
use League\Uri\Uri;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use TypeError;

use function array_filter;
use function array_key_exists;
use function base64_decode;
use function bin2hex;
use function explode;
use function is_array;
use function is_string;
use function random_bytes;
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
    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
        $this->privateKey = $privateKey;
    }

    public function setDefaultScope(string $scope): void
    {
        $this->defaultScope = $scope;
    }

    public function revokeRefreshTokens(bool $willRevoke): void
    {
        $this->revokeRefreshTokens = $willRevoke;
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

            if ($this->clientRepository->validateClient($clientId, $clientSecret, $this->getIdentifier()) === false) {
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

        if ($this->supportsGrantType($client, $this->getIdentifier()) === false) {
            throw OAuthServerException::unauthorizedClient();
        }

        return $client;
    }

    /**
     * Returns true if the given client is authorized to use the given grant type.
     */
    protected function supportsGrantType(ClientEntityInterface $client, string $grantType): bool
    {
        return method_exists($client, 'supportsGrantType') === false
            || $client->supportsGrantType($grantType) === true;
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
    public function validateScopes(string|array|null $scopes, ?string $redirectUri = null): array
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
        return array_filter(explode(self::SCOPE_DELIMITER_STRING, trim($scopes)), static fn ($scope) => $scope !== '');
    }

    /**
     * Apply RFC 8707 resource indicators as audience restrictions on an
     * access token that has been built by {@see buildAccessToken()} but not
     * yet persisted. Call this before {@see persistAccessToken()} so the
     * misconfiguration branch below fails fast and never leaves an orphaned
     * row behind in the token repository.
     *
     * @param list<non-empty-string> $audiences
     *
     * @throws LogicException When audiences are supplied but the entity does
     *                        not implement {@see AudienceRestrictedTokenInterface}.
     *                        This is a library-level misconfiguration, not a
     *                        protocol error, hence a programmer exception.
     */
    protected function applyResourceIndicators(AccessTokenEntityInterface $accessToken, array $audiences): void
    {
        if ($audiences === []) {
            // Intentional no-op: grants that do not process resource
            // indicators, or whose client omitted the `resource` parameter,
            // still call this method unconditionally. Short-circuiting here
            // lets them remain oblivious to the feature.
            return;
        }

        if (!$accessToken instanceof AudienceRestrictedTokenInterface) {
            throw new LogicException(
                'The access token entity must implement '
                . AudienceRestrictedTokenInterface::class
                . ' to support RFC 8707 resource indicators.'
            );
        }

        $accessToken->setAudiences($audiences);
    }

    /**
     * Parse and validate repeatable `resource` parameters per RFC 8707.
     *
     * Accepts either a single string or an array (PSR-7 normalizes repeated
     * query/body params to arrays). Each entry must be an absolute URI without
     * a fragment component.
     *
     * @param string|array<array-key, mixed>|null $raw Value as returned by
     *                                                 {@see getRawRequestParameter()} / {@see getRawQueryStringParameter()}.
     *
     * @throws OAuthServerException When any entry is not a valid absolute URI.
     *
     * @return list<non-empty-string> The normalized list of resource indicators (empty if none provided).
     */
    protected function parseResourceIndicators(string|array|null $raw, ?string $redirectUri = null): array
    {
        if ($raw === null || $raw === '' || $raw === []) {
            return [];
        }

        $values = is_string($raw) ? [$raw] : $raw;
        $resources = [];

        foreach ($values as $value) {
            $resources[] = $this->validateResourceIndicator($value, $redirectUri);
        }

        return $resources;
    }

    /**
     * Validate a single RFC 8707 `resource` entry as an absolute URI without
     * a fragment component.
     *
     * No trimming is performed: leading or trailing whitespace is treated as
     * an invalid indicator rather than silently normalized. This keeps the
     * exact-string comparison in
     * {@see AuthCodeGrant::resolveTokenEndpointResources()} symmetric — the
     * value stored in the auth code payload and the value presented at the
     * token endpoint must both survive this method unchanged.
     *
     * @throws OAuthServerException
     *
     * @return non-empty-string
     */
    private function validateResourceIndicator(mixed $value, ?string $redirectUri): string
    {
        if (!is_string($value)) {
            throw OAuthServerException::invalidTarget(
                'Resource indicator must be a string',
                $redirectUri
            );
        }

        if ($value === '') {
            throw OAuthServerException::invalidTarget(
                'Resource indicator must not be empty',
                $redirectUri
            );
        }

        if ($value !== trim($value)) {
            throw OAuthServerException::invalidTarget(
                'Resource indicator must not contain leading or trailing whitespace',
                $redirectUri
            );
        }

        try {
            $uri = Uri::new($value);
        } catch (SyntaxError) {
            throw OAuthServerException::invalidTarget(
                'Resource indicator must be a valid URI',
                $redirectUri
            );
        }

        $scheme = $uri->getScheme();
        if ($scheme === null || $scheme === '') {
            throw OAuthServerException::invalidTarget(
                'Resource indicator must be an absolute URI',
                $redirectUri
            );
        }

        $fragment = $uri->getFragment();
        if ($fragment !== null && $fragment !== '') {
            throw OAuthServerException::invalidTarget(
                'Resource indicator must not contain a fragment component',
                $redirectUri
            );
        }

        // RFC 8707 §2: the resource URI must not contain credentials; a
        // `userinfo` component (e.g. `https://user:pass@api.example.com/`)
        // would leak through the token response into logs and audit trails.
        $userInfo = $uri->getUserInfo();
        if ($userInfo !== null && $userInfo !== '') {
            throw OAuthServerException::invalidTarget(
                'Resource indicator must not contain a userinfo component',
                $redirectUri
            );
        }

        // RFC 8707 §2 says the URI "SHOULD NOT" include a query component.
        // We deliberately allow it: some APIs version themselves through
        // query strings (`https://api.example.com/?version=2`), and the
        // "SHOULD NOT" strength leaves the decision to the authorization
        // server. A future release may gate this behind a flag.

        return $value;
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
     * Retrieve a raw request parameter without coercion. Used for parameters
     * that may legitimately be repeated (and thus arrive as arrays), such as
     * the RFC 8707 `resource` parameter.
     *
     * @throws OAuthServerException When the value is neither null, string, nor array.
     *
     * @return string|array<array-key, mixed>|null
     */
    protected function getRawRequestParameter(string $parameter, ServerRequestInterface $request): string|array|null
    {
        return $this->extractRawParameterValue((array) $request->getParsedBody(), $parameter);
    }

    /**
     * Retrieve a raw query string parameter without coercion.
     *
     * @throws OAuthServerException When the value is neither null, string, nor array.
     *
     * @return string|array<array-key, mixed>|null
     */
    protected function getRawQueryStringParameter(string $parameter, ServerRequestInterface $request): string|array|null
    {
        return $this->extractRawParameterValue($request->getQueryParams(), $parameter);
    }

    /**
     * @param array<array-key, mixed> $source
     *
     * @throws OAuthServerException When the value is neither null, string, nor array.
     *
     * @return string|array<array-key, mixed>|null
     */
    private function extractRawParameterValue(array $source, string $parameter): string|array|null
    {
        $value = $source[$parameter] ?? null;

        if ($value === null || is_string($value) || is_array($value)) {
            return $value;
        }

        throw OAuthServerException::invalidRequest($parameter);
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
     * Issue an access token.
     *
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        string|null $userIdentifier,
        array $scopes = []
    ): AccessTokenEntityInterface {
        return $this->persistAccessToken(
            $this->buildAccessToken($accessTokenTTL, $client, $userIdentifier, $scopes)
        );
    }

    /**
     * Build and configure an access token entity without persisting it. Grants
     * that need to apply additional configuration (e.g. RFC 8707 resource
     * indicators) before the token hits storage can call this method, mutate
     * the returned entity, and then hand it to {@see persistAccessToken()}.
     *
     * @param ScopeEntityInterface[] $scopes
     */
    protected function buildAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        string|null $userIdentifier,
        array $scopes = []
    ): AccessTokenEntityInterface {
        $accessToken = $this->accessTokenRepository->getNewToken($client, $scopes, $userIdentifier);
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add($accessTokenTTL));
        $accessToken->setPrivateKey($this->privateKey);

        return $accessToken;
    }

    /**
     * Persist a fully configured access token entity, retrying on unique
     * identifier collisions.
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function persistAccessToken(AccessTokenEntityInterface $accessToken): AccessTokenEntityInterface
    {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

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
     * @param non-empty-string       $userIdentifier
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
        if ($this->supportsGrantType($accessToken->getClient(), 'refresh_token') === false) {
            return null;
        }

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
     * @return non-empty-string
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

    /**
     * {@inheritdoc}
     */
    public function setIntervalVisibility(bool $intervalVisibility): void
    {
        throw new LogicException('This grant does not support the interval parameter');
    }

    /**
     * {@inheritdoc}
     */
    public function getIntervalVisibility(): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function setIncludeVerificationUriComplete(bool $includeVerificationUriComplete): void
    {
        throw new LogicException('This grant does not support the verification_uri_complete parameter');
    }
}
