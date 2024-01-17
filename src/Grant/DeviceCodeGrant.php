<?php

/**
 * OAuth 2.0 Device Code grant.
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
use Error;
use Exception;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\DeviceCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\DeviceCodeResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;
use TypeError;

use function is_null;
use function json_decode;
use function json_encode;
use function property_exists;
use function random_int;
use function strlen;
use function time;

/**
 * Device Code grant class.
 */
class DeviceCodeGrant extends AbstractGrant
{
    protected DeviceCodeRepositoryInterface $deviceCodeRepository;
    private bool $intervalVisibility = false;
    private string $verificationUri;

    public function __construct(
        DeviceCodeRepositoryInterface $deviceCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private DateInterval $deviceCodeTTL,
        string $verificationUri,
        private int $retryInterval = 5
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

        $deviceCode = $this->issueDeviceCode(
            $this->deviceCodeTTL,
            $client,
            $this->verificationUri,
            $scopes
        );

        // TODO: Check payload generation
        $payload = [
            'device_code_id' => $deviceCode->getIdentifier(),
            'user_code' => $deviceCode->getUserCode(),
            'verification_uri' => $deviceCode->getVerificationUri(),
            'expire_time' => $deviceCode->getExpiryDateTime()->getTimestamp(),
            'client_id' => $deviceCode->getClient()->getIdentifier(),
            'scopes' => $deviceCode->getScopes(),
        ];

        $jsonPayload = json_encode($payload, JSON_THROW_ON_ERROR);

        $response = new DeviceCodeResponse();
        $response->setDeviceCode($deviceCode);
        $response->setPayload($this->encrypt($jsonPayload));

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    // TODO: Make sure this cant be abused to try and brute force a device code
    public function completeDeviceAuthorizationRequest(string $deviceCode, string $userId, bool $approved): void
    {
        $deviceCode = $this->deviceCodeRepository->getDeviceCodeEntityByDeviceCode($deviceCode);

        if ($deviceCode instanceof DeviceCodeEntityInterface === false) {
            throw OAuthServerException::invalidRequest('device_code', 'Device code does not exist');
        }

        if ($userId === '') {
            throw OAuthServerException::invalidRequest('user_id', 'User ID is required');
        }

        $deviceCode->setUserIdentifier($userId);
        $deviceCode->setUserApproved($approved);

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
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));
        $deviceCode = $this->validateDeviceCode($request, $client);

        $deviceCode->setLastPolledAt(new DateTimeImmutable());
        $this->deviceCodeRepository->persistDeviceCode($deviceCode);

        // If device code has no user associated, respond with pending
        if (is_null($deviceCode->getUserIdentifier())) {
            throw OAuthServerException::authorizationPending();
        }

        if ($deviceCode->getUserApproved() === false) {
            throw OAuthServerException::accessDenied();
        }

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, (string) $deviceCode->getUserIdentifier());

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, (string) $deviceCode->getUserIdentifier(), $finalizedScopes);
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);

        // Issue and persist new refresh token if given
        $refreshToken = $this->issueRefreshToken($accessToken);

        if ($refreshToken !== null) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request));
            $responseType->setRefreshToken($refreshToken);
        }

        $this->deviceCodeRepository->revokeDeviceCode($deviceCode->getIdentifier());

        return $responseType;
    }

    /**
     *
     * @throws OAuthServerException
     *
     */
    protected function validateDeviceCode(ServerRequestInterface $request, ClientEntityInterface $client): DeviceCodeEntityInterface
    {
        $encryptedDeviceCode = $this->getRequestParameter('device_code', $request);

        if (is_null($encryptedDeviceCode)) {
            throw OAuthServerException::invalidRequest('device_code');
        }

        $deviceCodePayload = $this->decodeDeviceCode($encryptedDeviceCode);

        if (!property_exists($deviceCodePayload, 'device_code_id')) {
            throw OAuthServerException::invalidRequest('device_code', 'Device code malformed');
        }

        if (time() > $deviceCodePayload->expire_time) {
            throw OAuthServerException::expiredToken('device_code');
        }

        if ($this->deviceCodeRepository->isDeviceCodeRevoked($deviceCodePayload->device_code_id) === true) {
            throw OAuthServerException::invalidRequest('device_code', 'Device code has been revoked');
        }

        if ($deviceCodePayload->client_id !== $client->getIdentifier()) {
            throw OAuthServerException::invalidRequest('device_code', 'Device code was not issued to this client');
        }

        $deviceCode = $this->deviceCodeRepository->getDeviceCodeEntityByDeviceCode(
            $deviceCodePayload->device_code_id
        );

        if ($deviceCode instanceof DeviceCodeEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidGrant();
        }

        if ($this->deviceCodePolledTooSoon($deviceCode->getLastPolledAt()) === true) {
            throw OAuthServerException::slowDown();
        }

        return $deviceCode;
    }

    private function deviceCodePolledTooSoon(?DateTimeImmutable $lastPoll): bool
    {
        return $lastPoll !== null && $lastPoll->getTimestamp() + $this->retryInterval > time();
    }

    /**
     *
     * @throws OAuthServerException
     *
     */
    protected function decodeDeviceCode(string $encryptedDeviceCode): stdClass
    {
        try {
            return json_decode($this->decrypt($encryptedDeviceCode));
        } catch (LogicException $e) {
            throw OAuthServerException::invalidRequest('device_code', 'Cannot decrypt the device code', $e);
        }
    }

    /**
     * Set the verification uri
     *
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
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueDeviceCode(
        DateInterval $deviceCodeTTL,
        ClientEntityInterface $client,
        string $verificationUri,
        array $scopes = []
    ): DeviceCodeEntityInterface {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $deviceCode = $this->deviceCodeRepository->getNewDeviceCode();
        $deviceCode->setExpiryDateTime((new DateTimeImmutable())->add($deviceCodeTTL));
        $deviceCode->setClient($client);
        $deviceCode->setVerificationUri($verificationUri);

        if ($this->getIntervalVisibility() === true) {
            $deviceCode->setInterval($this->retryInterval);
        }

        foreach ($scopes as $scope) {
            $deviceCode->addScope($scope);
        }

        while ($maxGenerationAttempts-- > 0) {
            $deviceCode->setIdentifier($this->generateUniqueIdentifier());
            $deviceCode->setUserCode($this->generateUniqueUserCode());
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
     * Generate a new unique user code.
     *
     *
     *
     * @throws OAuthServerException
     */
    protected function generateUniqueUserCode(int $length = 8): string
    {
        try {
            $userCode = '';
            $userCodeCharacters = 'BCDFGHJKLMNPQRSTVWXZ';

            while (strlen($userCode) < $length) {
                $userCode .= $userCodeCharacters[random_int(0, 19)];
            }

            return $userCode;
            // @codeCoverageIgnoreStart
        } catch (TypeError $e) {
            throw OAuthServerException::serverError('An unexpected error has occurred', $e);
        } catch (Error $e) {
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
}
