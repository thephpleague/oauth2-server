<?php
/**
 * OAuth 2.0 Password grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\MessageEncryption;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\Dto\EncryptedRefreshToken;
use League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Password grant class.
 */
class PasswordGrant extends AbstractGrant
{
    /**
     * @var MessageEncryption
     */
    private $messageEncryption;

    /**
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface         $userRepository
     * @param MessageEncryption                                                  $messageEncryption
     * @param \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        MessageEncryption $messageEncryption,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {
        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->refreshTokenTTL = new \DateInterval('P1M');
        $this->messageEncryption = $messageEncryption;
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->userRepository = $userRepository;
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
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request), $client);
        $user = $this->validateUser($request, $client);

        // Finalize the requested scopes
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $scopes);
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
     * @param \Psr\Http\Message\ServerRequestInterface                        $request
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface $client
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\UserEntityInterface
     */
    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client)
    {
        $username = $this->getRequestParameter('username', $request);
        if (is_null($username)) {
            throw OAuthServerException::invalidRequest('username', '`%s` parameter is missing');
        }

        $password = $this->getRequestParameter('password', $request);
        if (is_null($password)) {
            throw OAuthServerException::invalidRequest('password', '`%s` parameter is missing');
        }

        $user = $this->userRepository->getUserEntityByUserCredentials(
            $username,
            $password,
            $this->getIdentifier(),
            $client
        );
        if (!$user instanceof UserEntityInterface) {
            $this->getEmitter()->emit(new RequestEvent('user.authentication.failed', $request));

            throw OAuthServerException::invalidCredentials();
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'password';
    }
}
