<?php

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\MessageEncryption;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\Dto\AuthorizeData;
use League\OAuth2\Server\ResponseTypes\Dto\LoginData;
use League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;

class ImplicitGrant extends AbstractGrant
{
    /**
     * @var MessageEncryption
     */
    private $messageEncryption;

    /**
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface $userRepository
     * @param MessageEncryption                                          $messageEncryption
     */
    public function __construct(UserRepositoryInterface $userRepository, MessageEncryption $messageEncryption)
    {
        $this->setUserRepository($userRepository);
        $this->refreshTokenTTL = new \DateInterval('P1M');
        $this->messageEncryption = $messageEncryption;
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToRequest(ServerRequestInterface $request)
    {
        return (array_key_exists('response_type', $request->getQueryParams())
            && $request->getQueryParams()['response_type'] === 'token');
    }

    /**
     * Return the grant identifier that can be used in matching up requests.
     *
     * @return string
     */
    public function getIdentifier()
    {
        return 'implicit';
    }

    /**
     * {@inheritdoc}
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseFactoryInterface $responseFactory,
        \DateInterval $accessTokenTTL
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

        $stateParameter = $this->getQueryStringParameter('state', $request);

        // THe user approved the client, redirect them back with an access token
        if ($userHasApprovedClient === true) {

            // Finalize the requested scopes
            $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $userId);

            $accessToken = $this->issueAccessToken(
                $accessTokenTTL,
                $client,
                $userId,
                $scopes
            );

            return $responseFactory->newAccessTokenRedirectResponse($accessToken, $redirectUri, $stateParameter);
        }

        // The user denied the client, redirect them back with an error
        throw OAuthServerException::accessDenied('The user denied the request', (string) $redirectUri);
    }
}
