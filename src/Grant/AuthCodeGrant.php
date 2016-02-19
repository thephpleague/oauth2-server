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
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\Utils\KeyCrypt;
use League\Plates\Engine;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\Uri;

class AuthCodeGrant extends AbstractGrant
{
    /**
     * @var \DateInterval
     */
    private $authCodeTTL;

    /**
     * @var \League\OAuth2\Server\Repositories\UserRepositoryInterface
     */
    private $userRepository;

    /**
     * @var null|string
     */
    private $pathToLoginTemplate;

    /**
     * @var null|string
     */
    private $pathToAuthorizeTemplate;

    /**
     * @param \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface     $authCodeRepository
     * @param \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface         $userRepository
     * @param \DateInterval                                                      $authCodeTTL
     * @param string|null                                                        $pathToLoginTemplate
     * @param string|null                                                        $pathToAuthorizeTemplate
     */
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        UserRepositoryInterface $userRepository,
        \DateInterval $authCodeTTL,
        $pathToLoginTemplate = null,
        $pathToAuthorizeTemplate = null
    ) {
        $this->setAuthCodeRepository($authCodeRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->userRepository = $userRepository;
        $this->authCodeTTL = $authCodeTTL;
        $this->pathToLoginTemplate = ($pathToLoginTemplate === null)
            ? __DIR__.'/../ResponseTypes/DefaultTemplates/login_user.php'
            : $this->pathToLoginTemplate;
        $this->pathToAuthorizeTemplate = ($pathToLoginTemplate === null)
            ? __DIR__.'/../ResponseTypes/DefaultTemplates/authorize_client.php'
            : $this->pathToAuthorizeTemplate;
        $this->refreshTokenTTL = new \DateInterval('P1M');
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
        $client = $this->validateClient($request);

        if ($client instanceof ClientEntityInterface === false) {
            $this->emitter->emit(new Event('client.authentication.failed', $request));

            throw OAuthServerException::invalidClient();
        }

        $scopes = $this->validateScopes($request, $client, $client->getRedirectUri());
        $queryString = http_build_query($request->getQueryParams());
        $postbackUri = new Uri(
            sprintf(
                '//%s%s',
                $request->getServerParams()['HTTP_HOST'],
                $request->getServerParams()['REQUEST_URI']
            )
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
                $oauthCookiePayload = json_decode(KeyCrypt::decrypt($oauthCookie, $this->pathToPublicKey));
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
            $engine = new Engine(dirname($this->pathToLoginTemplate));
            $pathParts = explode(DIRECTORY_SEPARATOR, $this->pathToLoginTemplate);
            $html = $engine->render(
                end($pathParts),
                [
                    'error'        => $loginError,
                    'postback_uri' => (string) $postbackUri->withQuery($queryString),
                ]
            );

            return new Response\HtmlResponse($html);
        }

        // The user hasn't approved the client yet so show an authorize form
        if ($userId !== null && $userHasApprovedClient === null) {
            $engine = new Engine(dirname($this->pathToAuthorizeTemplate));
            $pathParts = explode(DIRECTORY_SEPARATOR, $this->pathToAuthorizeTemplate);
            $html = $engine->render(
                end($pathParts),
                [
                    'client'       => $client,
                    'scopes'       => $scopes,
                    'postback_uri' => (string) $postbackUri->withQuery($queryString),
                ]
            );

            return new Response\HtmlResponse(
                $html,
                200,
                [
                    'Set-Cookie' => sprintf(
                        'oauth_authorize_request=%s; Expires=%s',
                        urlencode(KeyCrypt::encrypt(
                            json_encode([
                                'user_id' => $userId,
                            ]),
                            $this->pathToPrivateKey
                        )),
                        (new \DateTime())->add(new \DateInterval('PT5M'))->format('D, d M Y H:i:s e')
                    ),
                ]
            );
        }

        $stateParameter = $this->getQueryStringParameter('state', $request);

        $redirectUri = new Uri($client->getRedirectUri());
        parse_str($redirectUri->getQuery(), $redirectPayload);
        if ($stateParameter !== null) {
            $redirectPayload['state'] = $stateParameter;
        }

        if ($userHasApprovedClient === true) {
            $authCode = $this->issueAuthCode(
                $this->authCodeTTL,
                $client,
                $userId,
                $redirectUri,
                $scopes
            );

            $redirectPayload['code'] = KeyCrypt::encrypt(
                json_encode(
                    [
                        'client_id'    => $authCode->getClient()->getIdentifier(),
                        'auth_code_id' => $authCode->getIdentifier(),
                        'scopes'       => $authCode->getScopes(),
                        'user_id'      => $authCode->getUserIdentifier(),
                        'expire_time'  => (new \DateTime())->add($this->authCodeTTL)->format('U'),
                    ]
                ),
                $this->pathToPrivateKey
            );

            return new Response\RedirectResponse($redirectUri->withQuery(http_build_query($redirectPayload)));
        }

        $exception = OAuthServerException::accessDenied('The user denied the request', (string) $redirectUri);

        return $exception->generateHttpResponse();
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
        $redirectUri = $this->getQueryStringParameter('redirect_uri', $request, null);
        if (is_null($redirectUri)) {
            throw OAuthServerException::invalidRequest('redirect_uri', null, '`%s` parameter is missing');
        }

        // Validate request
        $client = $this->validateClient($request);
        $encryptedAuthCode = $this->getRequestParameter('code', $request, null);

        if ($encryptedAuthCode === null) {
            throw OAuthServerException::invalidRequest('code');
        }

        // Validate the authorization code
        try {
            $authCodePayload = json_decode(KeyCrypt::decrypt($encryptedAuthCode, $this->pathToPublicKey));
            if (time() > $authCodePayload->expire_time) {
                throw OAuthServerException::invalidRequest('code', 'Authorization code has expired');
            }

            if ($this->getAuthCodeRepository()->isAuthCodeRevoked($authCodePayload->auth_code_id) === true) {
                throw OAuthServerException::invalidRequest('code', 'Authorization code has been revoked');
            }

            if ($authCodePayload->client_id !== $client->getIdentifier()) {
                throw OAuthServerException::invalidRequest('code', 'Authorization code was not issued to this client');
            }
        } catch (\LogicException  $e) {
            throw OAuthServerException::invalidRequest('code', null, 'Cannot decrypt the authorization code');
        }

        // Issue and persist access + refresh tokens
        $accessToken = $this->issueAccessToken(
            $accessTokenTTL,
            $client,
            $authCodePayload->user_id,
            $authCodePayload->scopes
        );
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Inject tokens into response type
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToRequest(ServerRequestInterface $request)
    {
        return
            (
                isset($request->getQueryParams()['response_type'])
                && $request->getQueryParams()['response_type'] === 'code'
                && isset($request->getQueryParams()['client_id'])
            ) || (parent::canRespondToRequest($request));
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

    /**
     * {@inheritdoc}
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        if (
            isset($request->getQueryParams()['response_type'])
            && $request->getQueryParams()['response_type'] === 'code'
            && isset($request->getQueryParams()['client_id'])
        ) {
            return $this->respondToAuthorizationRequest($request);
        } elseif (
            isset($request->getParsedBody()['grant_type'])
            && $request->getParsedBody()['grant_type'] === 'authorization_code'
        ) {
            return $this->respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
        } else {
            throw OAuthServerException::serverError('respondToRequest() should not have been called');
        }
    }
}
