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
namespace League\OAuth2\Server\Grant;

use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\Entities\AccessTokenEntity;
use League\OAuth2\Server\Entities\AuthCodeEntity;
use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntity;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Abstract grant class.
 */
abstract class AbstractGrant implements GrantTypeInterface
{
    use EmitterAwareTrait;

    const SCOPE_DELIMITER_STRING = ' ';

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
     * @var ScopeRepositoryInterface
     */
    protected $scopeRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface
     */
    protected $authCodeRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface
     */
    protected $refreshTokenRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\UserRepositoryInterface
     */
    protected $userRepository;

    /**
     * @var \DateInterval
     */
    protected $refreshTokenTTL;

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
     * @param \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function setRefreshTokenRepository(RefreshTokenRepositoryInterface $refreshTokenRepository)
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    /**
     * @param \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface $authCodeRepository
     */
    public function setAuthCodeRepository(AuthCodeRepositoryInterface $authCodeRepository)
    {
        $this->authCodeRepository = $authCodeRepository;
    }

    /**
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface $userRepository
     */
    public function setUserRepository(UserRepositoryInterface $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function setRefreshTokenTTL(\DateInterval $refreshTokenTTL)
    {
        $this->refreshTokenTTL = $refreshTokenTTL;
    }

    /**
     * Validate the client.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface
     */
    protected function validateClient(ServerRequestInterface $request)
    {
        $clientId = $this->getRequestParameter(
            'client_id',
            $request,
            $this->getServerParameter('PHP_AUTH_USER', $request)
        );
        if (is_null($clientId)) {
            throw OAuthServerException::invalidRequest('client_id', '`%s` parameter is missing');
        }

        // If the client is confidential require the client secret
        $clientSecret = $this->getRequestParameter(
            'client_secret',
            $request,
            $this->getServerParameter('PHP_AUTH_PW', $request)
        );

        $client = $this->clientRepository->getClientEntity(
            $clientId,
            $this->getIdentifier(),
            $clientSecret
        );

        if (!$client instanceof ClientEntityInterface) {
            $this->getEmitter()->emit(new RequestEvent('client.authentication.failed', $request));
            throw OAuthServerException::invalidClient();
        }

        // If a redirect URI is provided ensure it matches what is pre-registered
        $redirectUri = $this->getRequestParameter('redirect_uri', $request, null);
        if ($redirectUri !== null && (strcmp($client->getRedirectUri(), $redirectUri) !== 0)) {
            throw OAuthServerException::invalidClient();
        }

        return $client;
    }

    /**
     * Validate scopes in the request.
     *
     * @param string                                                          $scopes
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface $client
     * @param string                                                          $redirectUri
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface[]
     */
    public function validateScopes(
        $scopes,
        ClientEntityInterface $client,
        $redirectUri = null
    ) {
        $scopesList = array_filter(
            explode(self::SCOPE_DELIMITER_STRING, trim($scopes)),
            function ($scope) {
                return !empty($scope);
            }
        );

        $scopes = [];
        foreach ($scopesList as $scopeItem) {
            $scope = $this->scopeRepository->getScopeEntityByIdentifier($scopeItem);

            if (($scope instanceof ScopeEntityInterface) === false) {
                throw OAuthServerException::invalidScope($scopeItem, $redirectUri);
            }

            $scopes[] = $scope;
        }

        return $scopes;
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
        $requestParameters = (array) $request->getParsedBody();

        return isset($requestParameters[$parameter]) ? $requestParameters[$parameter] : $default;
    }

    /**
     * Retrieve query string parameter.
     *
     * @param string                                   $parameter
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param mixed                                    $default
     *
     * @return null|string
     */
    protected function getQueryStringParameter($parameter, ServerRequestInterface $request, $default = null)
    {
        return isset($request->getQueryParams()[$parameter]) ? $request->getQueryParams()[$parameter] : $default;
    }

    /**
     * Retrieve cookie parameter.
     *
     * @param string                                   $parameter
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param mixed                                    $default
     *
     * @return null|string
     */
    protected function getCookieParameter($parameter, ServerRequestInterface $request, $default = null)
    {
        return isset($request->getCookieParams()[$parameter]) ? $request->getCookieParams()[$parameter] : $default;
    }

    /**
     * Retrieve server parameter.
     *
     * @param string                                   $parameter
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param mixed                                    $default
     *
     * @return null|string
     */
    protected function getServerParameter($parameter, ServerRequestInterface $request, $default = null)
    {
        return isset($request->getServerParams()[$parameter]) ? $request->getServerParams()[$parameter] : $default;
    }

    /**
     * Issue an access token.
     *
     * @param \DateInterval                                                    $accessTokenTTL
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface  $client
     * @param string                                                           $userIdentifier
     * @param \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface[] $scopes
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    protected function issueAccessToken(
        \DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        $userIdentifier,
        array $scopes = []
    ) {
        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier($this->generateUniqueIdentifier());
        $accessToken->setExpiryDateTime((new \DateTime())->add($accessTokenTTL));
        $accessToken->setClient($client);
        $accessToken->setUserIdentifier($userIdentifier);

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        $this->accessTokenRepository->persistNewAccessToken($accessToken);

        return $accessToken;
    }

    /**
     * Issue an auth code.
     *
     * @param \DateInterval                                                    $authCodeTTL
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface  $client
     * @param string                                                           $userIdentifier
     * @param string                                                           $redirectUri
     * @param \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface[] $scopes
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\AuthCodeEntityInterface
     */
    protected function issueAuthCode(
        \DateInterval $authCodeTTL,
        ClientEntityInterface $client,
        $userIdentifier,
        $redirectUri,
        array $scopes = []
    ) {
        $authCode = new AuthCodeEntity();
        $authCode->setIdentifier($this->generateUniqueIdentifier());
        $authCode->setExpiryDateTime((new \DateTime())->add($authCodeTTL));
        $authCode->setClient($client);
        $authCode->setUserIdentifier($userIdentifier);
        $authCode->setRedirectUri($redirectUri);

        foreach ($scopes as $scope) {
            $authCode->addScope($scope);
        }

        $this->authCodeRepository->persistNewAuthCode($authCode);

        return $authCode;
    }

    /**
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessToken
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface
     */
    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken)
    {
        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier($this->generateUniqueIdentifier());
        $refreshToken->setExpiryDateTime((new \DateTime())->add($this->refreshTokenTTL));
        $refreshToken->setAccessToken($accessToken);

        $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);

        return $refreshToken;
    }

    /**
     * Generate a new unique identifier.
     *
     * @param int $length
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return string
     */
    protected function generateUniqueIdentifier($length = 40)
    {
        try {
            return bin2hex(random_bytes($length));
            // @codeCoverageIgnoreStart
        } catch (\TypeError $e) {
            throw OAuthServerException::serverError('An unexpected error has occurred');
        } catch (\Error $e) {
            throw OAuthServerException::serverError('An unexpected error has occurred');
        } catch (\Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            throw OAuthServerException::serverError('Could not generate a random string');
        }
        // @codeCoverageIgnoreEnd
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToRequest(ServerRequestInterface $request)
    {
        $requestParameters = (array) $request->getParsedBody();

        return (
            array_key_exists('grant_type', $requestParameters)
            && $requestParameters['grant_type'] === $this->getIdentifier()
        );
    }
}
