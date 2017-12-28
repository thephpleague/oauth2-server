<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

class ImplicitGrant extends AbstractAuthorizeGrant
{
    /**
     * @var \DateInterval
     */
    private $accessTokenTTL;

    /**
     * @var string
     */
    private $queryDelimiter;

    /**
     * @param \DateInterval $accessTokenTTL
     * @param string $queryDelimiter
     */
    public function __construct(\DateInterval $accessTokenTTL, $queryDelimiter = '#')
    {
        $this->accessTokenTTL = $accessTokenTTL;
        $this->queryDelimiter = $queryDelimiter;
    }

    /**
     * @param \DateInterval $refreshTokenTTL
     *
     * @throw \LogicException
     */
    public function setRefreshTokenTTL(\DateInterval $refreshTokenTTL)
    {
        throw new \LogicException('The Implicit Grant does not return refresh tokens');
    }

    /**
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     *
     * @throw \LogicException
     */
    public function setRefreshTokenRepository(RefreshTokenRepositoryInterface $refreshTokenRepository)
    {
        throw new \LogicException('The Implicit Grant does not return refresh tokens');
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAccessTokenRequest(ServerRequestInterface $request)
    {
        return false;
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
     * Respond to an incoming request.
     *
     * @param ServerRequestInterface $request
     * @param ResponseTypeInterface  $responseType
     * @param \DateInterval          $accessTokenTTL
     *
     * @return ResponseTypeInterface
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        throw new \LogicException('This grant does not used this method');
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request)
    {
        return (
            isset($request->getQueryParams()['response_type'])
            && $request->getQueryParams()['response_type'] === 'token'
            && isset($request->getQueryParams()['client_id'])
        );
    }

    /**
     * {@inheritdoc}
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request)
    {
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
            $this->getIdentifier(),
            null,
            false
        );

        if ($client instanceof ClientEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient();
        }

        $redirectUri = $this->getQueryStringParameter('redirect_uri', $request);
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
        } elseif (is_array($client->getRedirectUri()) && count($client->getRedirectUri()) !== 1
            || empty($client->getRedirectUri())
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient();
        }

        $scopes = $this->validateScopes(
            $this->getQueryStringParameter('scope', $request, $this->defaultScope),
            is_array($client->getRedirectUri())
                ? $client->getRedirectUri()[0]
                : $client->getRedirectUri()
        );

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes(
            $scopes,
            $this->getIdentifier(),
            $client
        );

        $stateParameter = $this->getQueryStringParameter('state', $request);

        $authorizationRequest = new AuthorizationRequest();
        $authorizationRequest->setGrantTypeId($this->getIdentifier());
        $authorizationRequest->setClient($client);
        $authorizationRequest->setRedirectUri($redirectUri);
        $authorizationRequest->setState($stateParameter);
        $authorizationRequest->setScopes($finalizedScopes);

        return $authorizationRequest;
    }

    /**
     * {@inheritdoc}
     */
    public function completeAuthorizationRequest(AuthorizationRequest $authorizationRequest)
    {
        if ($authorizationRequest->getUser() instanceof UserEntityInterface === false) {
            throw new \LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $finalRedirectUri = ($authorizationRequest->getRedirectUri() === null)
            ? is_array($authorizationRequest->getClient()->getRedirectUri())
                ? $authorizationRequest->getClient()->getRedirectUri()[0]
                : $authorizationRequest->getClient()->getRedirectUri()
            : $authorizationRequest->getRedirectUri();

        // The user approved the client, redirect them back with an access token
        if ($authorizationRequest->isAuthorizationApproved() === true) {
            $accessToken = $this->issueAccessToken(
                $this->accessTokenTTL,
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier(),
                $authorizationRequest->getScopes()
            );

            $response = new RedirectResponse();
            $response->setRedirectUri(
                $this->makeRedirectUri(
                    $finalRedirectUri,
                    [
                        'access_token' => (string) $accessToken->convertToJWT($this->privateKey),
                        'token_type'   => 'Bearer',
                        'expires_in'   => $accessToken->getExpiryDateTime()->getTimestamp() - (new \DateTime())->getTimestamp(),
                        'state'        => $authorizationRequest->getState(),
                    ],
                    $this->queryDelimiter
                )
            );

            return $response;
        }

        // The user denied the client, redirect them back with an error
        throw OAuthServerException::accessDenied(
            'The user denied the request',
            $this->makeRedirectUri(
                $finalRedirectUri,
                [
                    'state' => $authorizationRequest->getState(),
                ]
            )
        );
    }
}
