<?php

namespace League\OAuth2\Server\Grant;

use DateInterval;
use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\MessageEncryption;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\Dto\AuthorizeData;
use League\OAuth2\Server\ResponseTypes\Dto\CodeData;
use League\OAuth2\Server\ResponseTypes\Dto\EncryptedRefreshToken;
use League\OAuth2\Server\ResponseTypes\Dto\LoginData;
use League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthCodeGrant extends AbstractGrant
{
    /**
     * @var \DateInterval
     */
    private $authCodeTTL;
    /**
     * @var MessageEncryption
     */
    private $messageEncryption;

    /**
     * @param \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface     $authCodeRepository
     * @param \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface         $userRepository
     * @param MessageEncryption                                                  $messageEncryption
     * @param \DateInterval                                                      $authCodeTTL
     */
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        UserRepositoryInterface $userRepository,
        MessageEncryption $messageEncryption,
        \DateInterval $authCodeTTL
    ) {
        $this->setAuthCodeRepository($authCodeRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->setUserRepository($userRepository);
        $this->authCodeTTL = $authCodeTTL;
        $this->messageEncryption = $messageEncryption;
        $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * Respond to an authorization request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param ResponseFactoryInterface                 $responseFactory
     *
     * @throws OAuthServerException
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    protected function respondToAuthorizationRequest(
        ServerRequestInterface $request,
        ResponseFactoryInterface $responseFactory
    ) {
        $clientId = $this->getQueryStringParameter(
            'client_id',
            $request,
            $this->getServerParameter('PHP_AUTH_USER', $request)
        );
        if (is_null($clientId)) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        $client = $this->clientRepository->getClientEntity(
            $clientId,
            $this->getIdentifier()
        );

        if ($client instanceof ClientEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent('client.authentication.failed', $request));
            throw OAuthServerException::invalidClient();
        }

        $redirectUriParameter = $this->getQueryStringParameter('redirect_uri', $request, $client->getRedirectUri());
        if ($redirectUriParameter !== $client->getRedirectUri()) {
            $this->getEmitter()->emit(new RequestEvent('client.authentication.failed', $request));
            throw OAuthServerException::invalidClient();
        }

        $scopes = $this->validateScopes(
            $this->getQueryStringParameter('scope', $request),
            $client,
            $client->getRedirectUri()
        );

        $postbackUri = sprintf(
            '//%s%s',
            $request->getServerParams()['HTTP_HOST'],
            $request->getServerParams()['REQUEST_URI']
        );

        $userId = null;
        $userHasApprovedClient = null;
        if ($this->getRequestParameter('action', $request, null) !== null) {
            $userHasApprovedClient = ($this->getRequestParameter('action', $request) === 'approve');
        }

        // Check if the user has been authenticated
        $oauthCookie = $this->getCookieParameter('oauth_authorize_request', $request, null);
        if ($oauthCookie !== null) {
            try {
                $oauthCookiePayload = json_decode($this->messageEncryption->decrypt($oauthCookie));
                if (is_object($oauthCookiePayload)) {
                    $userId = $oauthCookiePayload->user_id;
                }
            } catch (\LogicException $e) {
                throw OAuthServerException::serverError($e->getMessage());
            }
        }

        // The username + password might be available in $_POST
        $usernameParameter = $this->getRequestParameter('username', $request, null);
        $passwordParameter = $this->getRequestParameter('password', $request, null);

        $loginError = null;

        // Assert if the user has logged in already
        if ($userId === null && $usernameParameter !== null && $passwordParameter !== null) {
            $userEntity = $this->userRepository->getUserEntityByUserCredentials(
                $usernameParameter,
                $passwordParameter,
                $this->getIdentifier(),
                $client
            );

            if ($userEntity instanceof UserEntityInterface) {
                $userId = $userEntity->getIdentifier();
            } else {
                $loginError = 'Incorrect username or password';
            }
        }

        // The user hasn't logged in yet so show a login form
        if ($userId === null) {
            return $responseFactory->newHtmlLoginResponse(
                new LoginData($loginError, $postbackUri, $request->getQueryParams())
            );
        }

        // The user hasn't approved the client yet so show an authorize form
        if ($userId !== null && $userHasApprovedClient === null) {
            $encryptedUserId = $this->messageEncryption->encrypt(
                json_encode([
                    'user_id' => $userId,
                ])
            );

            return $responseFactory->newHtmlAuthorizeResponse(
                new AuthorizeData($client, $scopes, $postbackUri, $request->getQueryParams(), $encryptedUserId)
            );
        }

        // The user has either approved or denied the client, so redirect them back
        $redirectUri = $client->getRedirectUri();

        // THe user approved the client, redirect them back with an auth code
        if ($userHasApprovedClient === true) {
            $stateParameter = $this->getQueryStringParameter('state', $request);

            // Finalize the requested scopes
            $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $userId);

            $authCode = $this->issueAuthCode(
                $this->authCodeTTL,
                $client,
                $userId,
                $redirectUri,
                $scopes
            );

            $code = $this->messageEncryption->encrypt(
                json_encode(
                    [
                        'client_id'    => $authCode->getClient()->getIdentifier(),
                        'redirect_uri' => $authCode->getRedirectUri(),
                        'auth_code_id' => $authCode->getIdentifier(),
                        'scopes'       => $authCode->getScopes(),
                        'user_id'      => $authCode->getUserIdentifier(),
                        'expire_time'  => (new \DateTime())->add($this->authCodeTTL)->format('U'),
                    ]
                )
            );

            return $responseFactory->newAuthCodeRedirectResponse(
                new CodeData($redirectUri, $code, $stateParameter)
            );
        }

        // The user denied the client, redirect them back with an error
        throw OAuthServerException::accessDenied('The user denied the request', (string) $redirectUri);
    }

    /**
     * Respond to an access token request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface                     $request
     * @param \League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface $responseFactory
     * @param \DateInterval                                                $accessTokenTTL
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     */
    protected function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseFactoryInterface $responseFactory,
        DateInterval $accessTokenTTL
    ) {
        // The redirect URI is required in this request
        $redirectUri = $this->getRequestParameter('redirect_uri', $request, null);
        if (is_null($redirectUri)) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }

        // Validate request
        $client = $this->validateClient($request);
        $encryptedAuthCode = $this->getRequestParameter('code', $request, null);

        if ($encryptedAuthCode === null) {
            throw OAuthServerException::invalidRequest('code');
        }

        // Validate the authorization code
        try {
            $authCodePayload = json_decode($this->messageEncryption->decrypt($encryptedAuthCode));
            if (time() > $authCodePayload->expire_time) {
                throw OAuthServerException::invalidRequest('code', 'Authorization code has expired');
            }

            if ($this->authCodeRepository->isAuthCodeRevoked($authCodePayload->auth_code_id) === true) {
                throw OAuthServerException::invalidRequest('code', 'Authorization code has been revoked');
            }

            if ($authCodePayload->client_id !== $client->getIdentifier()) {
                throw OAuthServerException::invalidRequest('code', 'Authorization code was not issued to this client');
            }

            if ($authCodePayload->redirect_uri !== $redirectUri) {
                throw OAuthServerException::invalidRequest('redirect_uri', 'Invalid redirect URI');
            }

            $scopes = [];
            foreach ($authCodePayload->scopes as $scopeId) {
                $scope = $this->scopeRepository->getScopeEntityByIdentifier($scopeId);

                if (!$scope) {
                    // @codeCoverageIgnoreStart
                    throw OAuthServerException::invalidScope($scopeId);
                    // @codeCoverageIgnoreEnd
                }

                $scopes[] = $scope;
            }
        } catch (\LogicException  $e) {
            throw OAuthServerException::invalidRequest('code', 'Cannot decrypt the authorization code');
        }

        // Issue and persist access + refresh tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $authCodePayload->user_id, $scopes);
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
     * {@inheritdoc}
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseFactoryInterface $responseFactory,
        \DateInterval $accessTokenTTL
    ) {
        if (
            array_key_exists('response_type', $request->getQueryParams())
            && $request->getQueryParams()['response_type'] === 'code'
        ) {
            return $this->respondToAuthorizationRequest($request, $responseFactory);
        }

        return $this->respondToAccessTokenRequest($request, $responseFactory, $accessTokenTTL);
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToRequest(ServerRequestInterface $request)
    {
        return
            (
                array_key_exists('response_type', $request->getQueryParams())
                && $request->getQueryParams()['response_type'] === 'code'
                && isset($request->getQueryParams()['client_id'])
            )
            || parent::canRespondToRequest($request);
    }

    /**
     * Return the grant identifier that can be used in matching up requests.
     *
     * @return string
     */
    public function getIdentifier()
    {
        return 'authorization_code';
    }
}
