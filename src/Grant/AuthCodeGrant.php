<?php

namespace League\OAuth2\Server\Grant;

use DateInterval;
use League\OAuth2\Server\Entities\ClientEntity;
use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
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
     * @var \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface
     */
    private $authCodeRepository;

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
     * @param \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface $authCodeRepository
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface     $userRepository
     * @param \DateInterval                                                  $authCodeTTL
     * @param string|null                                                    $pathToLoginTemplate
     * @param string|null                                                    $pathToAuthorizeTemplate
     */
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        UserRepositoryInterface $userRepository,
        \DateInterval $authCodeTTL,
        $pathToLoginTemplate = null,
        $pathToAuthorizeTemplate = null
    ) {
        $this->authCodeRepository = $authCodeRepository;
        $this->userRepository = $userRepository;
        $this->authCodeTTL = $authCodeTTL;
        $this->pathToLoginTemplate = $pathToLoginTemplate;
        $this->pathToAuthorizeTemplate = $pathToAuthorizeTemplate;
    }


    /**
     * Respond to an authorization request
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \Psr\Http\Message\ResponseInterface
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
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
            throw OAuthServerException::invalidRequest('client_id', null, '`%s` parameter is missing');
        }

        $redirectUri = $this->getQueryStringParameter('redirect_uri', $request, null);
        if (is_null($redirectUri)) {
            throw OAuthServerException::invalidRequest('redirect_uri', null, '`%s` parameter is missing');
        }

        $client = $this->clientRepository->getClientEntity(
            $clientId,
            null,
            $redirectUri,
            $this->getIdentifier()
        );

        if (!$client instanceof ClientEntityInterface) {
            $this->emitter->emit(new Event('client.authentication.failed', $request));

            throw OAuthServerException::invalidClient();
        }

        $scopes = $this->validateScopes($request, $client, $redirectUri);
        $queryString = http_build_query($request->getQueryParams());
        $postbackUri = new Uri(
            sprintf(
                '//%s%s',
                $request->getServerParams()['HTTP_HOST'],
                $request->getServerParams()['REQUEST_URI']
            )
        );

        $userId = null;
        $userHasApprovedClient = $userHasApprovedClient = $this->getRequestParameter('action', null);

        // Check if the user has been validated
        $oauthCookie = $this->getCookieParameter('oauth_authorize_request', $request, null);
        if ($oauthCookie !== null) {
            try {
                $oauthCookiePayload = json_decode(KeyCrypt::decrypt($oauthCookie, $this->pathToPublicKey));
                $userId = $oauthCookiePayload->user_id;
                $userHasApprovedClient = $oauthCookiePayload->client_is_authorized;
            } catch (\LogicException $e) {
                throw OAuthServerException::serverError($e->getMessage());
            }
        }

        // The username + password might be available in $_POST
        $usernameParameter = $this->getRequestParameter('username', null);
        $passwordParameter = $this->getRequestParameter('password', null);

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
            $engine = new Engine();
            $html = $engine->render(
                ($this->pathToLoginTemplate === null)
                    ? __DIR__ . '/../ResponseTypes/DefaultTemplates/login_user.php'
                    : $this->pathToLoginTemplate,
                [
                    'error'        => $loginError,
                    'postback_uri' => (string) $postbackUri->withQuery($queryString),
                ]
            );

            return new Response\HtmlResponse($html);
        }


        // The user hasn't approved the client yet so show an authorize form
        if ($userId !== null && $userHasApprovedClient === null) {
            $engine = new Engine();
            $html = $engine->render(
                ($this->pathToLoginTemplate === null)
                    ? __DIR__ . '/../ResponseTypes/DefaultTemplates/authorize_client.php'
                    : $this->pathToAuthorizeTemplate,
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
                        KeyCrypt::encrypt(
                            json_encode([
                                'user_id'              => $userId,
                                'client_is_authorized' => null,
                            ]),
                            $this->pathToPrivateKey
                        ),
                        (new \DateTime())->add(new \DateInterval('PT5M'))->format('D, d M Y H:i:s e')
                    ),
                ]
            );
        }

        $stateParameter = $this->getQueryStringParameter('state', $request);

        $redirectUri = new Uri($redirectUri);
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
            $this->authCodeRepository->persistNewAuthCode($authCode);

            $redirectPayload['code'] = KeyCrypt::encrypt(
                json_encode(
                    [
                        'client_id'    => $authCode->getClient()->getIdentifier(),
                        'auth_code_id' => $authCode->getIdentifier(),
                        'scopes'       => $authCode->getScopes(),
                        'user_id'      => $authCode->getUserIdentifier(),
                        'expire_time'  => $this->authCodeTTL->format('U'),
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
     * Respond to an access token request
     *
     * @param \Psr\Http\Message\ServerRequestInterface                  $request
     * @param \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface $responseType
     * @param \DateInterval                                             $accessTokenTTL
     *
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     */
    protected function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($request, $client);
        $encryptedAuthcode = $this->getRequestParameter('code', $request, null);

        if ($encryptedAuthcode === null) {
            throw OAuthServerException::invalidRequest('code');
        }

        // Validate the authorization code
        try {
            $authCodePayload = json_decode(KeyCrypt::decrypt($encryptedAuthcode, $this->pathToPrivateKey));
            if (time() > $authCodePayload->expire_time) {
                throw OAuthServerException::invalidRequest('code', 'Authorization code has expired');
            }
        } catch (\LogicException  $e) {
            throw OAuthServerException::invalidRequest('code');
        }

        $client = new ClientEntity();
        $client->setIdentifier($authCodePayload->client_id);

        // Issue and persist access token
        $accessToken = $this->issueAccessToken(
            $accessTokenTTL,
            $client,
            $authCodePayload->user_id,
            $authCodePayload->scopes
        );
        $this->accessTokenRepository->persistNewAccessToken($accessToken);

        // Inject access token into response type
        $responseType->setAccessToken($accessToken);

        return $responseType;
    }

    /**
     * @inheritdoc
     */
    public function canRespondToRequest(ServerRequestInterface $request)
    {
        return (
            (
                strtoupper($request->getMethod()) === 'GET'
                && isset($request->getQueryParams()['response_type'])
                && $request->getQueryParams()['response_type'] === 'code'
                && isset($request->getQueryParams()['client_id'])
            ) || (parent::canRespondToRequest($request))
        );
    }

    /**
     * Return the grant identifier that can be used in matching up requests
     *
     * @return string
     */
    public function getIdentifier()
    {
        return 'authorization_code';
    }

    /**
     * @inheritdoc
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
