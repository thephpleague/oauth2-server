<?php
/**
 * OAuth 2.0 Refresh token grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\MessageEncryption;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\Dto\EncryptedRefreshToken;
use League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Refresh token grant.
 */
class RefreshTokenGrant extends AbstractGrant
{
    /**
     * @var MessageEncryption
     */
    private $messageEncryption;

    /**
     * @param \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param MessageEncryption                                                  $messageEncryption
     */
    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        MessageEncryption $messageEncryption
    ) {
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->messageEncryption = $messageEncryption;
        $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseFactoryInterface $responseFactory,
        \DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $oldRefreshToken = $this->validateOldRefreshToken($request, $client->getIdentifier());
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request), $client);

        // If no new scopes are requested then give the access token the original session scopes
        if (count($scopes) === 0) {
            $scopes = array_map(function ($scopeId) use ($client) {
                $scope = $this->scopeRepository->getScopeEntityByIdentifier($scopeId);

                if (!$scope) {
                    // @codeCoverageIgnoreStart
                    throw OAuthServerException::invalidScope($scopeId);
                    // @codeCoverageIgnoreEnd
                }

                return $scope;
            }, $oldRefreshToken['scopes']);
        } else {
            // The OAuth spec says that a refreshed access token can have the original scopes or fewer so ensure
            // the request doesn't include any new scopes
            foreach ($scopes as $scope) {
                if (in_array($scope->getIdentifier(), $oldRefreshToken['scopes']) === false) {
                    throw OAuthServerException::invalidScope($scope->getIdentifier());
                }
            }
        }

        // Expire old tokens
        $this->accessTokenRepository->revokeAccessToken($oldRefreshToken['access_token_id']);
        $this->refreshTokenRepository->revokeRefreshToken($oldRefreshToken['refresh_token_id']);

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $oldRefreshToken['user_id'], $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);
        $expireDateTime = $accessToken->getExpiryDateTime()->getTimestamp();

        $encryptedRefreshToken = new EncryptedRefreshToken(
            $this->messageEncryption->encrypt(
                json_encode(
                    [
                        'client_id'        => $accessToken->getClient()->getIdentifier(),
                        'refresh_token_id' => $refreshToken->getIdentifier(),
                        'access_token_id'  => $accessToken->getIdentifier(),
                        'scopes'           => $accessToken->getScopes(),
                        'user_id'          => $accessToken->getUserIdentifier(),
                        'expire_time'      => $expireDateTime,
                    ]
                )
            )
        );

        return $responseFactory->newRefreshTokenResponse($accessToken, $encryptedRefreshToken);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string                                   $clientId
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return array
     */
    protected function validateOldRefreshToken(ServerRequestInterface $request, $clientId)
    {
        $encryptedRefreshToken = $this->getRequestParameter('refresh_token', $request);
        if (is_null($encryptedRefreshToken)) {
            throw OAuthServerException::invalidRequest('refresh_token');
        }

        // Validate refresh token
        try {
            $refreshToken = $this->messageEncryption->decrypt($encryptedRefreshToken);
        } catch (\LogicException $e) {
            throw OAuthServerException::invalidRefreshToken('Cannot parse refresh token: ' . $e->getMessage());
        }

        $refreshTokenData = json_decode($refreshToken, true);
        if ($refreshTokenData['client_id'] !== $clientId) {
            $this->getEmitter()->emit(new RequestEvent('refresh_token.client.failed', $request));
            throw OAuthServerException::invalidRefreshToken(
                'Token is not linked to client,' .
                ' got: ' . $clientId .
                ' expected: ' . $refreshTokenData['client_id']
            );
        }

        if ($refreshTokenData['expire_time'] < time()) {
            throw OAuthServerException::invalidRefreshToken('Token has expired');
        }

        if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshTokenData['refresh_token_id']) === true) {
            throw OAuthServerException::invalidRefreshToken('Token has been revoked');
        }

        return $refreshTokenData;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'refresh_token';
    }
}
