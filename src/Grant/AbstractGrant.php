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
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Abstract grant class.
 */
abstract class AbstractGrant implements GrantTypeInterface
{
    use EmitterAwareTrait, CryptTrait;

    const SCOPE_DELIMITER_STRING = ' ';

    const MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS = 10;

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
     * @var AuthCodeRepositoryInterface
     */
    protected $authCodeRepository;

    /**
     * @var RefreshTokenRepositoryInterface
     */
    protected $refreshTokenRepository;

    /**
     * @var UserRepositoryInterface
     */
    protected $userRepository;

    /**
     * @var \DateInterval
     */
    protected $refreshTokenTTL;

    /**
     * @var \League\OAuth2\Server\CryptKey
     */
    protected $privateKey;

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
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function setRefreshTokenRepository(RefreshTokenRepositoryInterface $refreshTokenRepository)
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    /**
     * @param AuthCodeRepositoryInterface $authCodeRepository
     */
    public function setAuthCodeRepository(AuthCodeRepositoryInterface $authCodeRepository)
    {
        $this->authCodeRepository = $authCodeRepository;
    }

    /**
     * @param UserRepositoryInterface $userRepository
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
     * Set the private key
     *
     * @param \League\OAuth2\Server\CryptKey $key
     */
    public function setPrivateKey(CryptKey $key)
    {
        $this->privateKey = $key;
    }

    /**
     * Validate the client.
     *
     * @param ServerRequestInterface $request
     *
     * @throws OAuthServerException
     *
     * @return ClientEntityInterface
     */
    protected function validateClient(ServerRequestInterface $request)
    {
        list($basicAuthUser, $basicAuthPassword) = $this->getBasicAuthCredentials($request);

        $clientId = $this->getRequestParameter('client_id', $request, $basicAuthUser);
        if (is_null($clientId)) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        // If the client is confidential require the client secret
        $clientSecret = $this->getRequestParameter('client_secret', $request, $basicAuthPassword);

        $client = $this->clientRepository->getClientEntity(
            $clientId,
            $this->getIdentifier(),
            $clientSecret,
            true
        );

        if ($client instanceof ClientEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient();
        }

        // If a redirect URI is provided ensure it matches what is pre-registered
        $redirectUri = $this->getRequestParameter('redirect_uri', $request, null);
        if ($redirectUri !== null) {
            if (
                is_string($client->getRedirectUri())
                && (strcmp($client->getRedirectUri(), $redirectUri) !== 0)
            ) {
                $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
                throw OAuthServerException::invalidClient();
            } elseif (
                is_array($client->getRedirectUri())
                && in_array($redirectUri, $client->getRedirectUri()) === false
            ) {
                $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
                throw OAuthServerException::invalidClient();
            }
        }

        return $client;
    }

    /**
     * Validate scopes in the request.
     *
     * @param string $scopes
     * @param string $redirectUri
     *
     * @throws OAuthServerException
     *
     * @return ScopeEntityInterface[]
     */
    public function validateScopes(
        $scopes,
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

            if ($scope instanceof ScopeEntityInterface === false) {
                throw OAuthServerException::invalidScope($scopeItem, $redirectUri);
            }

            $scopes[] = $scope;
        }

        return $scopes;
    }

    /**
     * Retrieve request parameter.
     *
     * @param string                 $parameter
     * @param ServerRequestInterface $request
     * @param mixed                  $default
     *
     * @return null|string
     */
    protected function getRequestParameter($parameter, ServerRequestInterface $request, $default = null)
    {
        $requestParameters = (array) $request->getParsedBody();

        return isset($requestParameters[$parameter]) ? $requestParameters[$parameter] : $default;
    }

    /**
     * Retrieve HTTP Basic Auth credentials with the Authorization header
     * of a request. First index of the returned array is the username,
     * second is the password (so list() will work). If the header does
     * not exist, or is otherwise an invalid HTTP Basic header, return
     * [null, null].
     *
     * @param ServerRequestInterface $request
     *
     * @return string[]|null[]
     */
    protected function getBasicAuthCredentials(ServerRequestInterface $request)
    {
        if (!$request->hasHeader('Authorization')) {
            return [null, null];
        }

        $header = $request->getHeader('Authorization')[0];
        if (strpos($header, 'Basic ') !== 0) {
            return [null, null];
        }

        if (!($decoded = base64_decode(substr($header, 6)))) {
            return [null, null];
        }

        if (strpos($decoded, ':') === false) {
            return [null, null]; // HTTP Basic header without colon isn't valid
        }

        return explode(':', $decoded, 2);
    }

    /**
     * Retrieve query string parameter.
     *
     * @param string                 $parameter
     * @param ServerRequestInterface $request
     * @param mixed                  $default
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
     * @param string                 $parameter
     * @param ServerRequestInterface $request
     * @param mixed                  $default
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
     * @param string                 $parameter
     * @param ServerRequestInterface $request
     * @param mixed                  $default
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
     * @param \DateInterval          $accessTokenTTL
     * @param ClientEntityInterface  $client
     * @param string                 $userIdentifier
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     *
     * @return AccessTokenEntityInterface
     */
    protected function issueAccessToken(
        \DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        $userIdentifier,
        array $scopes = []
    ) {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $accessToken = $this->accessTokenRepository->getNewToken($client, $scopes, $userIdentifier);
        $accessToken->setClient($client);
        $accessToken->setUserIdentifier($userIdentifier);
        $accessToken->setExpiryDateTime((new \DateTime())->add($accessTokenTTL));

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        while ($maxGenerationAttempts-- > 0) {
            $accessToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->accessTokenRepository->persistNewAccessToken($accessToken);

                return $accessToken;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }
    }

    /**
     * Issue an auth code.
     *
     * @param \DateInterval          $authCodeTTL
     * @param ClientEntityInterface  $client
     * @param string                 $userIdentifier
     * @param string                 $redirectUri
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     *
     * @return AuthCodeEntityInterface
     */
    protected function issueAuthCode(
        \DateInterval $authCodeTTL,
        ClientEntityInterface $client,
        $userIdentifier,
        $redirectUri,
        array $scopes = []
    ) {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $authCode = $this->authCodeRepository->getNewAuthCode();
        $authCode->setExpiryDateTime((new \DateTime())->add($authCodeTTL));
        $authCode->setClient($client);
        $authCode->setUserIdentifier($userIdentifier);
        $authCode->setRedirectUri($redirectUri);

        foreach ($scopes as $scope) {
            $authCode->addScope($scope);
        }

        while ($maxGenerationAttempts-- > 0) {
            $authCode->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->authCodeRepository->persistNewAuthCode($authCode);

                return $authCode;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }
    }

    /**
     * @param AccessTokenEntityInterface $accessToken
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     *
     * @return RefreshTokenEntityInterface
     */
    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken)
    {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $refreshToken = $this->refreshTokenRepository->getNewRefreshToken();
        $refreshToken->setExpiryDateTime((new \DateTime())->add($this->refreshTokenTTL));
        $refreshToken->setAccessToken($accessToken);

        while ($maxGenerationAttempts-- > 0) {
            $refreshToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);

                return $refreshToken;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }
    }

    /**
     * Generate a new unique identifier.
     *
     * @param int $length
     *
     * @throws OAuthServerException
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
    public function canRespondToAccessTokenRequest(ServerRequestInterface $request)
    {
        $requestParameters = (array) $request->getParsedBody();

        return (
            array_key_exists('grant_type', $requestParameters)
            && $requestParameters['grant_type'] === $this->getIdentifier()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request)
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request)
    {
        throw new \LogicException('This grant cannot validate an authorization request');
    }

    /**
     * {@inheritdoc}
     */
    public function completeAuthorizationRequest(AuthorizationRequest $authorizationRequest)
    {
        throw new \LogicException('This grant cannot complete an authorization request');
    }
}
