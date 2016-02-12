<?php

namespace League\OAuth2\Server\Grant;

use DateInterval;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\AuthorizeClientResponseTypeInterface;
use League\OAuth2\Server\ResponseTypes\LoginUserResponseTypeInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\Utils\KeyCrypt;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\Uri;

class AuthCodeGrant extends AbstractGrant
{
    /**
     * @var \League\OAuth2\Server\ResponseTypes\LoginUserResponseTypeInterface
     */
    private $loginUserResponseType;

    /**
     * @var \DateInterval
     */
    private $authCodeTTL;
    /**
     * @var \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface
     */
    private $authCodeRepository;
    /**
     * @var \League\OAuth2\Server\ResponseTypes\AuthorizeClientResponseTypeInterface
     */
    private $authorizeClientResponseType;

    /**
     * @param \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface           $authCodeRepository
     * @param \DateInterval                                                            $authCodeTTL
     * @param \League\OAuth2\Server\ResponseTypes\LoginUserResponseTypeInterface       $loginUserResponseType
     * @param \League\OAuth2\Server\ResponseTypes\AuthorizeClientResponseTypeInterface $authorizeClientResponseType
     */
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        \DateInterval $authCodeTTL,
        LoginUserResponseTypeInterface $loginUserResponseType,
        AuthorizeClientResponseTypeInterface $authorizeClientResponseType
    ) {
        $this->authCodeRepository = $authCodeRepository;
        $this->authCodeTTL = $authCodeTTL;
        $this->loginUserResponseType = $loginUserResponseType;
        $this->authorizeClientResponseType = $authorizeClientResponseType;
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

        // Check if the user has been validated
        $userIdCookieParam = $this->getCookieParameter('oauth_user_id', $request, null);
        if ($userIdCookieParam === null) {
            return $this->loginUserResponseType->handle($client, $scopes, $queryString, $this->pathToPrivateKey);
        } else {
            try {
                $userId = KeyCrypt::decrypt($userIdCookieParam, $this->pathToPublicKey);
            } catch (\LogicException $e) {
                throw OAuthServerException::serverError($e->getMessage());
            }
        }

        // Check the user has approved the request
        $userApprovedCookieParam = $this->getCookieParameter('oauth_user_approved_client', $request, null);
        if ($userApprovedCookieParam === null) {
            return $this->authorizeClientResponseType->handle($client, $scopes, $queryString, $this->pathToPrivateKey);
        } else {
            try {
                $userApprovedClient = KeyCrypt::decrypt($userApprovedCookieParam, $this->pathToPublicKey);
            } catch (\LogicException $e) {
                throw OAuthServerException::serverError($e->getMessage());
            }
        }

        $stateParameter = $this->getQueryStringParameter('state', $request);

        $redirectUri = new Uri($redirectUri);
        parse_str($redirectUri->getQuery(), $redirectPayload);
        if ($stateParameter !== null) {
            $redirectPayload['state'] = $stateParameter;
        }

        if ($userApprovedClient === 1) {
            $authCode = $this->issueAuthCode(
                $this->authCodeTTL,
                $client,
                $userId,
                $redirectUri,
                $scopes
            );
            $this->authCodeRepository->persistNewAuthCode($authCode);

            $redirectPayload['code'] = $authCode->getIdentifier();

            return new Response(
                'php://memory',
                302,
                [
                    'Location' => $redirectUri->withQuery(http_build_query($redirectPayload)),
                ]
            );
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
