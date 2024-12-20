<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Grant;

use DateInterval;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

use function count;
use function is_array;
use function is_null;
use function time;

class ImplicitGrant extends AbstractAuthorizeGrant
{
    public function __construct(private DateInterval $accessTokenTTL, private string $queryDelimiter = '#')
    {
    }

    /**
     * @throws LogicException
     */
    public function setRefreshTokenTTL(DateInterval $refreshTokenTTL): void
    {
        throw new LogicException('The Implicit Grant does not return refresh tokens');
    }

    /**
     * @throws LogicException
     */
    public function setRefreshTokenRepository(RefreshTokenRepositoryInterface $refreshTokenRepository): void
    {
        throw new LogicException('The Implicit Grant does not return refresh tokens');
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAccessTokenRequest(ServerRequestInterface $request): bool
    {
        return false;
    }

    /**
     * Return the grant identifier that can be used in matching up requests.
     */
    public function getIdentifier(): string
    {
        return 'implicit';
    }

    /**
     * Respond to an incoming request.
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        throw new LogicException('This grant does not used this method');
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
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
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $clientId = $this->getQueryStringParameter(
            'client_id',
            $request,
            $this->getServerParameter('PHP_AUTH_USER', $request)
        );

        if (is_null($clientId)) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        $client = $this->getClientEntityOrFail($clientId, $request);

        $redirectUri = $this->getQueryStringParameter('redirect_uri', $request);

        if ($redirectUri !== null) {
            $this->validateRedirectUri($redirectUri, $client, $request);
        } elseif (
            $client->getRedirectUri() === '' ||
            (is_array($client->getRedirectUri()) && count($client->getRedirectUri()) !== 1)
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient($request);
        }

        $stateParameter = $this->getQueryStringParameter('state', $request);

        $scopes = $this->validateScopes(
            $this->getQueryStringParameter('scope', $request, $this->defaultScope),
            $this->makeRedirectUri(
                $redirectUri ?? $this->getClientRedirectUri($client),
                $stateParameter !== null ? ['state' => $stateParameter] : [],
                $this->queryDelimiter
            )
        );

        $authorizationRequest = $this->createAuthorizationRequest();
        $authorizationRequest->setGrantTypeId($this->getIdentifier());
        $authorizationRequest->setClient($client);
        $authorizationRequest->setRedirectUri($redirectUri);

        if ($stateParameter !== null) {
            $authorizationRequest->setState($stateParameter);
        }

        $authorizationRequest->setScopes($scopes);

        return $authorizationRequest;
    }

    /**
     * {@inheritdoc}
     */
    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        if ($authorizationRequest->getUser() instanceof UserEntityInterface === false) {
            throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $finalRedirectUri = $authorizationRequest->getRedirectUri()
                          ?? $this->getClientRedirectUri($authorizationRequest->getClient());

        // The user approved the client, redirect them back with an access token
        if ($authorizationRequest->isAuthorizationApproved() === true) {
            // Finalize the requested scopes
            $finalizedScopes = $this->scopeRepository->finalizeScopes(
                $authorizationRequest->getScopes(),
                $this->getIdentifier(),
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier()
            );

            $accessToken = $this->issueAccessToken(
                $this->accessTokenTTL,
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier(),
                $finalizedScopes
            );

            // TODO: next major release: this method needs `ServerRequestInterface` as an argument
            // $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));

            $response = new RedirectResponse();
            $response->setRedirectUri(
                $this->makeRedirectUri(
                    $finalRedirectUri,
                    [
                        'access_token' => $accessToken->toString(),
                        'token_type'   => 'Bearer',
                        'expires_in'   => $accessToken->getExpiryDateTime()->getTimestamp() - time(),
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
                ],
                $this->queryDelimiter
            )
        );
    }
}
