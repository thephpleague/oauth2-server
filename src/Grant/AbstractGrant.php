<?php
/**
 * OAuth 2.0 Abstract grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\Event\EmitterInterface;
use League\Event\Event;
use League\OAuth2\Server\Entities\AccessTokenEntity;
use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntity;
use League\OAuth2\Server\Entities\ScopeEntity;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Utils\SecureKey;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Abstract grant class
 */
abstract class AbstractGrant implements GrantTypeInterface
{
    /**
     * Grant identifier
     *
     * @var string
     */
    protected $identifier = '';

    /**
     * Grant responds with
     *
     * @var string
     */
    protected $respondsWith = 'token';

    /**
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * @var ClientRepositoryInterface
     */
    protected $clientRepository;

    /**
     * @var AccessTokenRepositoryInterface
     */
    protected $accessTokenRepository;

    /**
     * @var \League\Event\Emitter
     */
    protected $emitter;

    /**
     * @var ScopeRepositoryInterface
     */
    protected $scopeRepository;

    /**
     * @param ClientRepositoryInterface $clientRepository
     */
    public function setClientRepository(ClientRepositoryInterface $clientRepository)
    {
        $this->clientRepository = $clientRepository;
    }

    /**
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository)
    {
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * @param ScopeRepositoryInterface $scopeRepository
     */
    public function setScopeRepository(ScopeRepositoryInterface $scopeRepository)
    {
        $this->scopeRepository = $scopeRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * {@inheritdoc}
     */
    public function respondsWith()
    {
        return $this->respondsWith;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function validateClient(ServerRequestInterface $request)
    {
        $clientId = $this->getRequestParameter(
            'client_id',
            $request,
            $this->getServerParameter('PHP_AUTH_USER', $request)
        );
        if (is_null($clientId)) {
            throw OAuthServerException::invalidRequest('client_id', null, '`%s` parameter is missing');
        }

        $clientSecret = $this->getRequestParameter(
            'client_secret',
            $request,
            $this->getServerParameter('PHP_AUTH_PW', $request)
        );
        if (is_null($clientSecret)) {
            throw OAuthServerException::invalidRequest('client_secret', null, '`%s` parameter is missing');
        }

        $client = $this->clientRepository->getClientEntity(
            $clientId,
            $clientSecret,
            null,
            $this->getIdentifier()
        );

        if (!$client instanceof ClientEntityInterface) {
            $this->emitter->emit(new Event('client.authentication.failed', $request));

            throw OAuthServerException::invalidClient();
        }

        return $client;
    }

    /**
     * Retrieve request parameter.
     *
     * @param string                                   $parameter
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param mixed                                    $default
     *
     * @return null|string
     */
    protected function getRequestParameter($parameter, ServerRequestInterface $request, $default = null)
    {
        return (isset($request->getParsedBody()[$parameter])) ? $request->getParsedBody()[$parameter] : $default;
    }

    /**
     * Retrieve server parameter.
     *
     * @param string|array                             $parameter
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param mixed                                    $default
     *
     * @return null|string
     */
    protected function getServerParameter($parameter, ServerRequestInterface $request, $default = null)
    {
        return (isset($request->getServerParams()[$parameter])) ? $request->getServerParams()[$parameter] : $default;
    }

    /**
     * @param string                $scopeParamValue      A string containing a delimited set of scope identifiers
     * @param string                $scopeDelimiterString The delimiter between the scopes in the value string
     * @param ClientEntityInterface $client
     * @param string                $redirectUri
     *
     * @return \League\OAuth2\Server\Entities\ScopeEntity[]
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function validateScopes(
        $scopeParamValue,
        $scopeDelimiterString,
        ClientEntityInterface $client,
        $redirectUri = null
    ) {
        $scopesList = array_filter(
            explode($scopeDelimiterString, trim($scopeParamValue)),
            function ($scope) {
                return !empty($scope);
            }
        );

        $scopes = [];
        foreach ($scopesList as $scopeItem) {
            $scope = $this->scopeRepository->getScopeEntityByIdentifier(
                $scopeItem,
                $this->getIdentifier(),
                $client->getIdentifier()
            );

            if (($scope instanceof ScopeEntity) === false) {
                throw OAuthServerException::invalidScope($scopeItem, null, null, $redirectUri);
            }

            $scopes[] = $scope;
        }

        return $scopes;
    }

    /**
     * @inheritdoc
     */
    public function setEmitter(EmitterInterface $emitter)
    {
        $this->emitter = $emitter;
    }

    /**
     * @param \DateInterval                                                   $tokenTTL
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface $client
     * @param string                                                          $userIdentifier
     * @param array                                                           $scopes
     *
     * @return \League\OAuth2\Server\Entities\AccessTokenEntity
     */
    protected function issueAccessToken(
        \DateInterval $tokenTTL,
        ClientEntityInterface $client,
        $userIdentifier,
        array $scopes = []
    ) {
        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier(SecureKey::generate());
        $accessToken->setExpiryDateTime((new \DateTime())->add($tokenTTL));
        $accessToken->setClient($client);
        $accessToken->setUserIdentifier($userIdentifier);

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        return $accessToken;
    }

    /**
     * @param \League\OAuth2\Server\Entities\AccessTokenEntity $accessToken
     *
     * @return \League\OAuth2\Server\Entities\RefreshTokenEntity
     */
    protected function issueRefreshToken(AccessTokenEntity $accessToken)
    {
        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier(SecureKey::generate());
        $refreshToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('P1M')));
        $refreshToken->setAccessToken($accessToken);

        return $refreshToken;
    }

    /**
     * @inheritdoc
     */
    public function canRespondToRequest(ServerRequestInterface $request)
    {
        return (
            isset($request->getParsedBody()['grant_type'])
            && $request->getParsedBody()['grant_type'] === $this->identifier
        );
    }
}
