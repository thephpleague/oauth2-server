<?php

namespace League\OAuth2\Server\Grant;

use DateInterval;
use DateTime;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthCodeGrant extends AbstractGrant
{
    /**
     * @inheritdoc
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $tokenTTL,
        $scopeDelimiter = ' '
    ) {
        if (
            isset($request->getQueryParams()['response_type'])
            && $request->getQueryParams()['response_type'] === 'code'
            && isset($request->getQueryParams()['client_id'])
        ) {
            return $this->respondToAuthorizationRequest($request, $scopeDelimiter, $tokenTTL);
        } elseif (
            isset($request->getParsedBody()['grant_type'])
            && $request->getParsedBody()['grant_type'] === 'authorization_code'
        ) {
            return $this->respondToAccessTokenRequest($request, $responseType, $tokenTTL);
        } else {
            throw OAuthServerException::serverError('respondToRequest() should not have been called');
        }
    }

    /**
     * Respond to an authorization request
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string                                   $scopeDelimiter
     * @param DateTime                                 $tokenTTL
     */
    protected function respondToAuthorizationRequest(
        ServerRequestInterface $request,
        $scopeDelimiter = ' ',
        DateTime $tokenTTL
    ) {
        // Get required params
        /*$clientId = array_key_exists('client_id', $request->getQueryParams())
            ? $request->getQueryParams()['client_id'] // $_GET['client_id']
            : null;

        if (is_null($clientId)) {
            throw OAuthServerException::invalidRequest('client_id', null, '`%s` parameter is missing');
        }

        $redirectUri = array_key_exists('redirect_uri', $request->getQueryParams())
            ? $request->getQueryParams()['redirect_uri'] // $_GET['redirect_uri']
            : null;

        if (is_null($redirectUri)) {
            throw OAuthServerException::invalidRequest('redirect_uri', null, '`%s` parameter is missing');
        }

        // Validate client ID and redirect URI
        $client = $this->clientRepository->getClientEntity(
            $clientId,
            $this->getIdentifier(),
            null,
            $redirectUri
        );

        if (($client instanceof ClientEntityInterface) === false) {
            throw OAuthServerException::invalidClient();
        }

        $state = array_key_exists('state', $request->getQueryParams())
            ? $request->getQueryParams()['state'] // $_GET['state']
            : null;

        // Validate any scopes that are in the request
        $scopeParam = array_key_exists('scope', $request->getQueryParams())
            ? $request->getQueryParams()['scope'] // $_GET['scope']
            : '';
        $scopes = $this->validateScopes($scopeParam, $scopeDelimiter, $client);

        // Create a new authorization code
        $authCode = new AuthCodeEntity();
        $authCode->setIdentifier(SecureKey::generate());
        $authCode->setExpiryDateTime((new \DateTime())->add($authCodeTTL));
        $authCode->setClient($client);
        $authCode->setUserIdentifier($userEntity->getIdentifier());

        // Associate scopes with the session and access token
        foreach ($scopes as $scope) {
            $authCode->addScope($scope);
        }*/
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
            ) || (
                isset($request->getParsedBody()['grant_type'])
                && $request->getParsedBody()['grant_type'] === 'authorization_code'
            )
        );
    }
}
