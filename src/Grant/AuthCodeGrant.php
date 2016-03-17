<?php

namespace League\OAuth2\Server\Grant;

use DateInterval;
use League\Event\Event;
use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\HtmlResponse;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\TemplateRenderer\RendererInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthCodeGrant extends AbstractAuthorizeGrant
{
    /**
     * @var \DateInterval
     */
    private $authCodeTTL;

    /**
     * @param \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface     $authCodeRepository
     * @param \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface         $userRepository
     * @param \DateInterval                                                      $authCodeTTL
     * @param \League\OAuth2\Server\TemplateRenderer\RendererInterface|null      $templateRenderer
     */
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        UserRepositoryInterface $userRepository,
        \DateInterval $authCodeTTL,
        RendererInterface $templateRenderer = null
    ) {
        $this->setAuthCodeRepository($authCodeRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->setUserRepository($userRepository);
        $this->authCodeTTL = $authCodeTTL;
        $this->refreshTokenTTL = new \DateInterval('P1M');
        $this->templateRenderer = $templateRenderer;
    }

    /**
     * Respond to an authorization request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    protected function respondToAuthorizationRequest(
        ServerRequestInterface $request
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
            $this->getEmitter()->emit(new Event('client.authentication.failed', $request));

            throw OAuthServerException::invalidClient();
        }

        $redirectUriParameter = $this->getQueryStringParameter('redirect_uri', $request, $client->getRedirectUri());
        if ($redirectUriParameter !== $client->getRedirectUri()) {
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
                $oauthCookiePayload = json_decode($this->decrypt($oauthCookie));
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
                $passwordParameter
            );

            if ($userEntity instanceof UserEntityInterface) {
                $userId = $userEntity->getIdentifier();
            } else {
                $loginError = 'Incorrect username or password';
            }
        }

        // The user hasn't logged in yet so show a login form
        if ($userId === null) {
            $html = $this->getTemplateRenderer()->renderLogin([
                'error'        => $loginError,
                'postback_uri' => $this->makeRedirectUri(
                    $postbackUri,
                    $request->getQueryParams()
                ),
            ]);

            $htmlResponse = new HtmlResponse($this->accessTokenRepository);
            $htmlResponse->setStatusCode(403);
            $htmlResponse->setHtml($html);

            return $htmlResponse;
        }

        // The user hasn't approved the client yet so show an authorize form
        if ($userId !== null && $userHasApprovedClient === null) {
            $html = $this->getTemplateRenderer()->renderAuthorize([
                'client'       => $client,
                'scopes'       => $scopes,
                'postback_uri' => $this->makeRedirectUri(
                    $postbackUri,
                    $request->getQueryParams()
                ),
            ]);

            $htmlResponse = new HtmlResponse($this->accessTokenRepository);
            $htmlResponse->setStatusCode(200);
            $htmlResponse->setHtml($html);
            $htmlResponse->setHeader('set-cookie', sprintf(
                'oauth_authorize_request=%s; Expires=%s',
                urlencode($this->encrypt(
                    json_encode([
                        'user_id' => $userId,
                    ])
                )),
                (new \DateTime())->add(new \DateInterval('PT5M'))->format('D, d M Y H:i:s e')
            ));

            return $htmlResponse;
        }

        // The user has either approved or denied the client, so redirect them back
        $redirectUri = $client->getRedirectUri();
        $redirectPayload = [];

        $stateParameter = $this->getQueryStringParameter('state', $request);
        if ($stateParameter !== null) {
            $redirectPayload['state'] = $stateParameter;
        }

        // THe user approved the client, redirect them back with an auth code
        if ($userHasApprovedClient === true) {
            $authCode = $this->issueAuthCode(
                $this->authCodeTTL,
                $client,
                $userId,
                $redirectUri,
                $scopes
            );

            $redirectPayload['code'] = $this->encrypt(
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

            $response = new RedirectResponse($this->accessTokenRepository);
            $response->setRedirectUri(
                $this->makeRedirectUri(
                    $redirectUri,
                    $redirectPayload
                )
            );

            return $response;
        }

        // The user denied the client, redirect them back with an error
        throw OAuthServerException::accessDenied('The user denied the request', (string) $redirectUri);
    }

    /**
     * Respond to an access token request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface                  $request
     * @param \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface $responseType
     * @param \DateInterval                                             $accessTokenTTL
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     */
    protected function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
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
            $authCodePayload = json_decode($this->decrypt($encryptedAuthCode));
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
                $scope = $this->scopeRepository->getScopeEntityByIdentifier(
                    $scopeId,
                    $this->getIdentifier(),
                    $client->getIdentifier()
                );

                if (!$scope) {
                    throw OAuthServerException::invalidScope($scopeId);
                }

                $scopes[] = $scope;
            }
        } catch (\LogicException  $e) {
            throw OAuthServerException::invalidRequest('code', 'Cannot decrypt the authorization code');
        }

        // Issue and persist access + refresh tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $authCodePayload->user_id, $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Inject tokens into response type
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;
    }

    /**
     * {@inheritdoc}
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        if (
            array_key_exists('response_type', $request->getQueryParams())
            && $request->getQueryParams()['response_type'] === 'code'
        ) {
            return $this->respondToAuthorizationRequest($request);
        }

        return $this->respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
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
