<?php
/**
 * OAuth 2.0 Password grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\Event\Event;
use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Password grant class
 */
class PasswordGrant extends AbstractGrant
{
    /**
     * Grant identifier
     *
     * @var string
     */
    protected $identifier = 'password';

    /**
     * @var \League\OAuth2\Server\Repositories\UserRepositoryInterface
     */
    private $userRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface
     */
    private $refreshTokenRepository;

    /**
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface         $userRepository
     * @param \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {
        $this->userRepository = $userRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    /**
     * @inheritdoc
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $tokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $user = $this->validateUser($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request), $client);

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($tokenTTL, $client, $user->getIdentifier(), $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);
        $this->accessTokenRepository->persistNewAccessToken($accessToken);
        $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);

        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\UserEntityInterface
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function validateUser(ServerRequestInterface $request)
    {
        $username = $this->getRequestParameter('username', $request);
        if (is_null($username)) {
            throw OAuthServerException::invalidRequest('username', null, '`%s` parameter is missing');
        }

        $password = $this->getRequestParameter('password', $request);
        if (is_null($password)) {
            throw OAuthServerException::invalidRequest('password', null, '`%s` parameter is missing');
        }

        $user = $this->userRepository->getUserEntityByUserCredentials($username, $password);
        if (!$user instanceof UserEntityInterface) {
            $this->emitter->emit(new Event('user.authentication.failed', $request));

            throw OAuthServerException::invalidCredentials();
        }

        return $user;
    }
}
