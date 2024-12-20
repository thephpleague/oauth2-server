<?php

/**
 * OAuth 2.0 Device Code grant.
 *
 * @author      Andrew Millington <andrew@noexceptions.io>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Grant;

use DateInterval;
use DateTimeImmutable;
use Error;
use Exception;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\DeviceCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestRefreshTokenEvent;
use League\OAuth2\Server\ResponseTypes\DeviceCodeResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use TypeError;

use function is_null;
use function random_int;
use function strlen;
use function time;

/**
 * Device Code grant class.
 */
class DeviceCodeGrant extends AbstractGrant
{
    protected DeviceCodeRepositoryInterface $deviceCodeRepository;
    private bool $includeVerificationUriComplete = false;
    private bool $intervalVisibility = false;
    private string $verificationUri;

    public function __construct(
        DeviceCodeRepositoryInterface $deviceCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private DateInterval $deviceCodeTTL,
        string $verificationUri,
        private readonly int $retryInterval = 5
    ) {
        $this->setDeviceCodeRepository($deviceCodeRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->refreshTokenTTL = new DateInterval('P1M');

        $this->setVerificationUri($verificationUri);
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToDeviceAuthorizationRequest(ServerRequestInterface $request): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function respondToDeviceAuthorizationRequest(ServerRequestInterface $request): DeviceCodeResponse
    {
        $clientId = $this->getRequestParameter(
            'client_id',
            $request,
            $this->getServerParameter('PHP_AUTH_USER', $request)
        );

        if ($clientId === null) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        $client = $this->getClientEntityOrFail($clientId, $request);

        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));

        $deviceCodeEntity = $this->issueDeviceCode(
            $this->deviceCodeTTL,
            $client,
            $this->verificationUri,
            $scopes
        );

        $response = new DeviceCodeResponse();

        if ($this->includeVerificationUriComplete === true) {
            $response->includeVerificationUriComplete();
        }

        if ($this->intervalVisibility === true) {
            $response->includeInterval();
        }

        $response->setDeviceCodeEntity($deviceCodeEntity);

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function completeDeviceAuthorizationRequest(string $deviceCode, string $userId, bool $userApproved): void
    {
        $deviceCode = $this->deviceCodeRepository->getDeviceCodeEntityByDeviceCode($deviceCode);

        if ($deviceCode instanceof DeviceCodeEntityInterface === false) {
            throw OAuthServerException::invalidRequest('device_code', 'Device code does not exist');
        }

        if ($userId === '') {
            throw OAuthServerException::invalidRequest('user_id', 'User ID is required');
        }

        $deviceCode->setUserIdentifier($userId);
        $deviceCode->setUserApproved($userApproved);

        $this->deviceCodeRepository->persistDeviceCode($deviceCode);
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        // Validate request
        $client = $this->validateClient($request);
        $deviceCodeEntity = $this->validateDeviceCode($request, $client);

        // If device code has no user associated, respond with pending or slow down
        if (is_null($deviceCodeEntity->getUserIdentifier())) {
            $shouldSlowDown = $this->deviceCodePolledTooSoon($deviceCodeEntity->getLastPolledAt());

            $deviceCodeEntity->setLastPolledAt(new DateTimeImmutable());
            $this->deviceCodeRepository->persistDeviceCode($deviceCodeEntity);

            if ($shouldSlowDown) {
                throw OAuthServerException::slowDown();
            }

            throw OAuthServerException::authorizationPending();
        }

        if ($deviceCodeEntity->getUserApproved() === false) {
            throw OAuthServerException::accessDenied();
        }

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($deviceCodeEntity->getScopes(), $this->getIdentifier(), $client, $deviceCodeEntity->getUserIdentifier());

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $deviceCodeEntity->getUserIdentifier(), $finalizedScopes);
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));
        $responseType->setAccessToken($accessToken);

        // Issue and persist new refresh token if given
        $refreshToken = $this->issueRefreshToken($accessToken);

        if ($refreshToken !== null) {
            $this->getEmitter()->emit(new RequestRefreshTokenEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request, $refreshToken));
            $responseType->setRefreshToken($refreshToken);
        }

        $this->deviceCodeRepository->revokeDeviceCode($deviceCodeEntity->getIdentifier());

        return $responseType;
    }

    /**
     * @throws OAuthServerException
     */
    protected function validateDeviceCode(ServerRequestInterface $request, ClientEntityInterface $client): DeviceCodeEntityInterface
    {
        $deviceCode = $this->getRequestParameter('device_code', $request);

        if (is_null($deviceCode)) {
            throw OAuthServerException::invalidRequest('device_code');
        }

        $deviceCodeEntity = $this->deviceCodeRepository->getDeviceCodeEntityByDeviceCode(
            $deviceCode
        );

        if ($deviceCodeEntity instanceof DeviceCodeEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidGrant();
        }

        if (time() > $deviceCodeEntity->getExpiryDateTime()->getTimestamp()) {
            throw OAuthServerException::expiredToken('device_code');
        }

        if ($this->deviceCodeRepository->isDeviceCodeRevoked($deviceCode) === true) {
            throw OAuthServerException::invalidRequest('device_code', 'Device code has been revoked');
        }

        if ($deviceCodeEntity->getClient()->getIdentifier() !== $client->getIdentifier()) {
            throw OAuthServerException::invalidRequest('device_code', 'Device code was not issued to this client');
        }

        return $deviceCodeEntity;
    }

    private function deviceCodePolledTooSoon(?DateTimeImmutable $lastPoll): bool
    {
        return $lastPoll !== null && $lastPoll->getTimestamp() + $this->retryInterval > time();
    }

    /**
     * Set the verification uri
     */
    public function setVerificationUri(string $verificationUri): void
    {
        $this->verificationUri = $verificationUri;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier(): string
    {
        return 'urn:ietf:params:oauth:grant-type:device_code';
    }

    private function setDeviceCodeRepository(DeviceCodeRepositoryInterface $deviceCodeRepository): void
    {
        $this->deviceCodeRepository = $deviceCodeRepository;
    }

    /**
     * Issue a device code.
     *
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueDeviceCode(
        DateInterval $deviceCodeTTL,
        ClientEntityInterface $client,
        string $verificationUri,
        array $scopes = [],
    ): DeviceCodeEntityInterface {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $deviceCode = $this->deviceCodeRepository->getNewDeviceCode();
        $deviceCode->setExpiryDateTime((new DateTimeImmutable())->add($deviceCodeTTL));
        $deviceCode->setClient($client);
        $deviceCode->setVerificationUri($verificationUri);
        $deviceCode->setInterval($this->retryInterval);

        foreach ($scopes as $scope) {
            $deviceCode->addScope($scope);
        }

        while ($maxGenerationAttempts-- > 0) {
            $deviceCode->setIdentifier($this->generateUniqueIdentifier());
            $deviceCode->setUserCode($this->generateUserCode());

            try {
                $this->deviceCodeRepository->persistDeviceCode($deviceCode);

                return $deviceCode;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }

        // This should never be hit. It is here to work around a PHPStan false error
        return $deviceCode;
    }

    /**
     * Generate a new user code.
     *
     * @throws OAuthServerException
     */
    protected function generateUserCode(int $length = 8): string
    {
        try {
            $userCode = '';
            $userCodeCharacters = 'BCDFGHJKLMNPQRSTVWXZ';

            while (strlen($userCode) < $length) {
                $userCode .= $userCodeCharacters[random_int(0, 19)];
            }

            return $userCode;
            // @codeCoverageIgnoreStart
        } catch (TypeError | Error $e) {
            throw OAuthServerException::serverError('An unexpected error has occurred', $e);
        } catch (Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            throw OAuthServerException::serverError('Could not generate a random string', $e);
        }
        // @codeCoverageIgnoreEnd
    }

    public function setIntervalVisibility(bool $intervalVisibility): void
    {
        $this->intervalVisibility = $intervalVisibility;
    }

    public function getIntervalVisibility(): bool
    {
        return $this->intervalVisibility;
    }

    public function setIncludeVerificationUriComplete(bool $includeVerificationUriComplete): void
    {
        $this->includeVerificationUriComplete = $includeVerificationUriComplete;
    }
}
