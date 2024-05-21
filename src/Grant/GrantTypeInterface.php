<?php

/**
 * OAuth 2.0 Grant type interface.
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
use Defuse\Crypto\Key;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\EventEmitting\EmitterAwareInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\DeviceCodeResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Grant type interface.
 */
interface GrantTypeInterface extends EmitterAwareInterface
{
    /**
     * Set refresh token TTL.
     */
    public function setRefreshTokenTTL(DateInterval $refreshTokenTTL): void;

    /**
     * Return the grant identifier that can be used in matching up requests.
     */
    public function getIdentifier(): string;

    /**
     * Respond to an incoming request.
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface;

    /**
     * The grant type should return true if it is able to respond to an authorization request
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool;

    /**
     * If the grant can respond to an authorization request this method should be called to validate the parameters of
     * the request.
     *
     * If the validation is successful an AuthorizationRequest object will be returned. This object can be safely
     * serialized in a user's session, and can be used during user authentication and authorization.
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface;

    /**
     * Once a user has authenticated and authorized the client the grant can complete the authorization request.
     * The AuthorizationRequest object's $userId property must be set to the authenticated user and the
     * $authorizationApproved property must reflect their desire to authorize or deny the client.
     */
    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface;

    /**
     * The grant type should return true if it is able to respond to this request.
     *
     * For example most grant types will check that the $_POST['grant_type'] property matches it's identifier property.
     */
    public function canRespondToAccessTokenRequest(ServerRequestInterface $request): bool;

    /**
     * The grant type should return true if it is able to respond to a device authorization request
     */
    public function canRespondToDeviceAuthorizationRequest(ServerRequestInterface $request): bool;

    /**
     * If the grant can respond to a device authorization request this method should be called to validate the parameters of
     * the request.
     *
     * If the validation is successful a DeviceAuthorizationRequest object will be returned. This object can be safely
     * serialized in a user's session, and can be used during user authentication and authorization.
     */
    public function respondToDeviceAuthorizationRequest(ServerRequestInterface $request): DeviceCodeResponse;

    /**
     * If the grant can respond to a device authorization request this method should be called to validate the parameters of
     * the request.
     *
     * If the validation is successful a DeviceCode object is persisted.
     */
    public function completeDeviceAuthorizationRequest(string $deviceCode, string $userId, bool $userApproved): void;

    /**
     * Set the client repository.
     */
    public function setClientRepository(ClientRepositoryInterface $clientRepository): void;

    /**
     * Set the access token repository.
     */
    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository): void;

    /**
     * Set the scope repository.
     */
    public function setScopeRepository(ScopeRepositoryInterface $scopeRepository): void;

    /**
     * Set the default scope.
     */
    public function setDefaultScope(string $scope): void;

    /**
     * Set the path to the private key.
     */
    public function setPrivateKey(CryptKeyInterface $privateKey): void;

    public function setEncryptionKey(Key|string|null $key = null): void;

    /**
     * Enable or prevent the revocation of refresh tokens upon usage.
     */
    public function revokeRefreshTokens(bool $willRevoke): void;

    /**
     * If set, the minimum interval between device code polling will be
     * returned by the server.
     */
    public function setIntervalVisibility(bool $intervalVisibility): void;

    /**
     * Checks if the minimum interval between device code polling should be
     * returned by the server.
     */
    public function getIntervalVisibility(): bool;

    /**
     * If set, the server will return a full verification URI to the client.
     * This is useful when your device authorization endpoint might not be able
     * to enter the user code easily.
     */
    public function setIncludeVerificationUriComplete(bool $includeVerificationUriComplete): void;
}
