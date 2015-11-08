<?php
/**
 * OAuth 2.0 Auth code grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\Event\Emitter;
use League\Event\Event;
use League\OAuth2\Server\Entities\AccessTokenEntity;
use League\OAuth2\Server\Entities\Interfaces\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Exception\InvalidClientException;
use League\OAuth2\Server\Exception\InvalidRequestException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\TokenTypes\TokenTypeInterface;
use League\OAuth2\Server\Utils\SecureKey;
use Symfony\Component\HttpFoundation\Request;
use DateInterval;

/**
 * Auth code grant class
 */
class AuthCodeGrant extends AbstractGrant
{
    /**
     * @var \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface
     */
    protected $authCodeRepository;

    /**
     * @param \League\Event\Emitter                                              $emitter
     * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface       $clientRepository
     * @param \League\OAuth2\Server\Repositories\ScopeRepositoryInterface        $scopeRepository
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface  $accessTokenRepository
     * @param \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface     $authCodeRepository
     * @param \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        Emitter $emitter,
        ClientRepositoryInterface $clientRepository,
        ScopeRepositoryInterface $scopeRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository = null
    ) {
        $this->authCodeRepository = $authCodeRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
        parent::__construct($emitter, $clientRepository, $scopeRepository, $accessTokenRepository);
    }

    /**
     * Grant identifier
     *
     * @var string
     */
    protected $identifier = 'authorization_code';

    /**
     * Response type
     *
     * @var string
     */
    protected $responseType = 'code';

    /**
     * AuthServer instance
     *
     * @var \League\OAuth2\Server\AuthorizationServer
     */
    protected $server = null;

    /**
     * Access token expires in override
     *
     * @var int
     */
    protected $accessTokenTTL = null;

    /**
     * The TTL of the auth token
     *
     * @var integer
     */
    protected $authTokenTTL = 600;

    /**
     * Override the default access token expire time
     *
     * @param int $authTokenTTL
     *
     * @return void
     */
    public function setAuthTokenTTL($authTokenTTL)
    {
        $this->authTokenTTL = $authTokenTTL;
    }

    /**
     * Check authorize parameters
     *
     * @return array Authorize request parameters
     *
     * @throws
     */
    /*public function checkAuthorizeParams()
    {
        // Get required params
        $clientId = $request->query->get('client_id', null);
        if (is_null($clientId)) {
            throw new InvalidRequestException('client_id');
        }

        $redirectUri = $request->query->get('redirect_uri', null);
        if (is_null($redirectUri)) {
            throw new InvalidRequestException('redirect_uri');
        }

        // Validate client ID and redirect URI
        $client = $this->server->getClientStorage()->get(
            $clientId,
            null,
            $redirectUri,
            $this->getIdentifier()
        );

        if (($client instanceof ClientEntity) === false) {
            $this->server->getEventEmitter()->emit(new Event\ClientAuthenticationFailedEvent($request));
            throw new Exception\InvalidClientException();
        }

        $state = $request->query->get('state', null);
        if ($this->server->stateParamRequired() === true && is_null($state)) {
            throw new InvalidRequestException('state', $redirectUri);
        }

        $responseType = $request->query->get('response_type', null);
        if (is_null($responseType)) {
            throw new InvalidRequestException('response_type', $redirectUri);
        }

        // Ensure response type is one that is recognised
        if (!in_array($responseType, $this->server->getResponseTypes())) {
            throw new Exception\UnsupportedResponseTypeException($responseType, $redirectUri);
        }

        // Validate any scopes that are in the request
        $scopeParam = $request->query->get('scope', '');
        $scopes = $this->validateScopes($scopeParam, $client, $redirectUri);

        return [
            'client'        => $client,
            'redirect_uri'  => $redirectUri,
            'state'         => $state,
            'response_type' => $responseType,
            'scopes'        => $scopes
        ];
    }*/

    /**
     * Parse a new authorize request
     *
     * @param string $type       The session owner's type
     * @param string $typeId     The session owner's ID
     * @param array  $authParams The authorize request $_GET parameters
     *
     * @return string An authorisation code
     */
    /*public function newAuthorizeRequest($type, $typeId, $authParams = [])
    {
        // Create a new session
        $session = new SessionEntity($this->server);
        $session->setOwner($type, $typeId);
        $session->associateClient($authParams['client']);
        $session->save();

        // Create a new auth code
        $authCode = new AuthCodeEntity($this->server);
        $authCode->setId(SecureKey::generate());
        $authCode->setRedirectUri($authParams['redirect_uri']);
        $authCode->setExpireTime(time() + $this->authTokenTTL);

        foreach ($authParams['scopes'] as $scope) {
            $authCode->associateScope($scope);
        }

        $authCode->setSession($session);
        $authCode->save();

        return $authCode->generateRedirectUri($authParams['state']);
    }*/

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
     * @throws \League\OAuth2\Server\Exception\InvalidGrantException
     * @throws \League\OAuth2\Server\Exception\InvalidRequestException
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
            throw new InvalidRequestException('client_id', '');
        }

        $clientSecret = $request->request->get('client_secret', $request->getPassword());
        if (is_null($clientSecret)) {
            throw new InvalidRequestException('client_secret');
        }

        $redirectUri = $request->request->get('redirect_uri', null);
        if (is_null($redirectUri)) {
            throw new InvalidRequestException('redirect_uri');
        }

        // Validate client ID and client secret
        $client = $this->clientRepository->get(
            $clientId,
            $clientSecret,
            $redirectUri,
            $this->getIdentifier()
        );

        if (($client instanceof ClientEntityInterface) === false) {
            $this->emitter->emit(new Event('client.authentication.failed', $request));
            throw new InvalidClientException();
        }

        // Validate the auth code
        $authCode = $request->request->get('code', null);
        if (is_null($authCode)) {
            throw new InvalidRequestException('code');
        }

        $code = $this->authCodeRepository->get($authCode);
        if (($code instanceof AuthCodeEntityInterface) === false) {
            throw new InvalidRequestException('code');
        }

        // Ensure the auth code hasn't expired
        if ($code->isExpired() === true) {
            throw new InvalidRequestException('code');
        }

        // Check redirect URI presented matches redirect URI originally used in authorize request
        if ($code->getRedirectUri() !== $redirectUri) {
            throw new InvalidRequestException('redirect_uri');
        }

        // Generate the access token
        $accessToken = new AccessTokenEntity($this->server);
        $accessToken->setIdentifier(SecureKey::generate());
        $expirationDateTime = (new \DateTime())->add($accessTokenTTL);
        $accessToken->setExpiryDateTime($expirationDateTime);
        $accessToken->setClient($client);

        foreach ($code->getScopes() as $scope) {
            $accessToken->addScope($scope);
        }

        $tokenType->setAccessToken($accessToken);

        // Associate a refresh token if set
        if ($this->refreshTokenRepository instanceof RefreshTokenRepositoryInterface) {
//            $refreshToken = new RefreshTokenEntity($this->server);
//            $refreshToken->setId(SecureKey::generate());
//            $refreshToken->setExpireTime($this->server->getGrantType('refresh_token')->getRefreshTokenTTL() + time());
//            $tokenType->setParam('refresh_token', $refreshToken->getId());
//            $refreshToken->setAccessToken($accessToken);
        }

        // Expire the auth code
        $this->authCodeRepository->delete($code);

        // Save the access token
        $this->accessTokenRepository->create($accessToken);

        return $tokenType;
    }
}
