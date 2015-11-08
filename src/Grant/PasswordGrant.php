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

use DateInterval;
use League\Event\Emitter;
use League\Event\Event;
use League\OAuth2\Server\Entities\AccessTokenEntity;
use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\TokenTypes\TokenTypeInterface;
use League\OAuth2\Server\Utils\SecureKey;
use Symfony\Component\HttpFoundation\Request;

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
     * Callback to authenticate a user's name and password
     *
     * @var callable
     */
    protected $callback;

    /**
     * @var \League\OAuth2\Server\Repositories\UserRepositoryInterface
     */
    protected $userRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface
     */
    protected $refreshTokenRepository;

    /**
     * @param \League\Event\Emitter                                              $emitter
     * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface       $clientRepository
     * @param \League\OAuth2\Server\Repositories\ScopeRepositoryInterface        $scopeRepository
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface  $accessTokenRepository
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface         $userRepository
     * @param \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        Emitter $emitter,
        ClientRepositoryInterface $clientRepository,
        ScopeRepositoryInterface $scopeRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository = null
    ) {
        $this->userRepository = $userRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
        parent::__construct($emitter, $clientRepository, $scopeRepository, $accessTokenRepository);
    }

    /**
     * Return an access token
     *
     * @param \Symfony\Component\HttpFoundation\Request           $request
     * @param \League\OAuth2\Server\TokenTypes\TokenTypeInterface $tokenType
     * @param \DateInterval                                       $accessTokenTTL
     * @param string                                              $scopeDelimiter
     *
     * @return \League\OAuth2\Server\TokenTypes\TokenTypeInterface
     * @throws \League\OAuth2\Server\Exception\InvalidClientException
     * @throws \League\OAuth2\Server\Exception\InvalidCredentialsException
     * @throws \League\OAuth2\Server\Exception\InvalidRequestException
     * @throws \League\OAuth2\Server\Exception\InvalidScopeException
     */
    public function getAccessTokenAsType(
        Request $request,
        TokenTypeInterface $tokenType,
        DateInterval $accessTokenTTL,
        $scopeDelimiter = ' '
    ) {
        // Get the required params
        $clientId = $request->request->get('client_id', $request->getUser());
        if (is_null($clientId)) {
            throw new Exception\InvalidRequestException('client_id');
        }

        $clientSecret = $request->request->get('client_secret', $request->getPassword());
        if (is_null($clientSecret)) {
            throw new Exception\InvalidRequestException('client_secret');
        }

        // Validate client ID and client secret
        $client = $this->clientRepository->get(
            $clientId,
            $clientSecret,
            null,
            $this->getIdentifier()
        );

        if (($client instanceof ClientEntityInterface) === false) {
            $this->emitter->emit(new Event('client.authentication.failed', $request));
            throw new Exception\InvalidClientException();
        }

        $username = $request->request->get('username', null);
        if (is_null($username)) {
            throw new Exception\InvalidRequestException('username');
        }

        $password = $request->request->get('password', null);
        if (is_null($password)) {
            throw new Exception\InvalidRequestException('password');
        }

        // Check if user's username and password are correct
        $user = $this->userRepository->getByCredentials($username, $password);

        if (($user instanceof UserEntityInterface) === false) {
            $this->emitter->emit(new Event('user.authentication.failed', $request));
            throw new Exception\InvalidCredentialsException();
        }

        // Validate any scopes that are in the request
        $scopeParamValue = $request->request->get('scope', '');
        $scopes = $this->validateScopes($scopeParamValue, $scopeDelimiter, $client);

        // Generate an access token
        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier(SecureKey::generate());
        $expirationDateTime = (new \DateTime())->add($accessTokenTTL);
        $accessToken->setExpiryDateTime($expirationDateTime);
        $accessToken->setOwner('user', $user->getIdentifier());
        $accessToken->setClient($client);

        // Associate scopes with the access token
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        $tokenType->setAccessToken($accessToken);

        // Associate a refresh token if set
        if ($this->refreshTokenRepository instanceof RefreshTokenRepositoryInterface) {
//            $refreshToken = new RefreshTokenEntity($this->server);
//            $refreshToken->setId(SecureKey::generate());
//            $refreshToken->setExpireTime($this->server->getGrantType('refresh_token')->getRefreshTokenTTL() + time());
//            $refreshToken->setAccessToken($accessToken);
//            $this->server->getTokenType()->setParam('refresh_token', $refreshToken->getId());
//            $tokenType->setParam('refresh_token', $refreshToken);
        }

        // Save the access token
        $this->accessTokenRepository->create($accessToken);

        // Inject the access token into token type
        $tokenType->setAccessToken($accessToken);

        return $tokenType;
    }
}
