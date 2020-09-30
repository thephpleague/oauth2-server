<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;

trait RequestValidatorTrait
{
    /**
     * Get the Emitter.
     *
     * @return \League\Event\EmitterInterface
     */
    abstract public function getEmitter();

    /**
     * @return \League\OAuth2\Server\Repositories\ClientRepositoryInterface
     */
    abstract public function getClientRepository();

    /**
     * Return the grant identifier that can be used in matching up requests.
     *
     * @return string
     */
    abstract public function getIdentifier();

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
        list($clientId, $clientSecret) = $this->getClientCredentials($request);

        if ($this->clientRepository->validateClient($clientId, $clientSecret, $this->getIdentifier()) === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidClient($request);
        }

        $client = $this->getClientEntityOrFail($clientId, $request);

        // If a redirect URI is provided ensure it matches what is pre-registered
        $redirectUri = $this->getRequestParameter('redirect_uri', $request, null);

        if ($redirectUri !== null) {
            $this->validateRedirectUri($redirectUri, $client, $request);
        }

        return $client;
    }

    /**
     * Wrapper around ClientRepository::getClientEntity() that ensures we emit
     * an event and throw an exception if the repo doesn't return a client
     * entity.
     *
     * This is a bit of defensive coding because the interface contract
     * doesn't actually enforce non-null returns/exception-on-no-client so
     * getClientEntity might return null. By contrast, this method will
     * always either return a ClientEntityInterface or throw.
     *
     * @param string                 $clientId
     * @param ServerRequestInterface $request
     *
     * @return ClientEntityInterface
     */
    protected function getClientEntityOrFail($clientId, ServerRequestInterface $request)
    {
        $client = $this->clientRepository->getClientEntity($clientId);

        if ($client instanceof ClientEntityInterface === false || empty($client->getRedirectUri())) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient($request);
        }

        return $client;
    }

    /**
     * Validate redirectUri from the request.
     * If a redirect URI is provided ensure it matches what is pre-registered
     *
     * @param string                 $redirectUri
     * @param ClientEntityInterface  $client
     * @param ServerRequestInterface $request
     *
     * @throws OAuthServerException
     */
    protected function validateRedirectUri(
        string $redirectUri,
        ClientEntityInterface $client,
        ServerRequestInterface $request
    ) {
        if (\is_string($client->getRedirectUri())
            && (\strcmp($client->getRedirectUri(), $redirectUri) !== 0)
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient($request);
        } elseif (\is_array($client->getRedirectUri())
            && \in_array($redirectUri, $client->getRedirectUri(), true) === false
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient($request);
        }
    }

    /**
     * Gets the client credentials from the request from the request body or
     * the Http Basic Authorization header
     *
     * @param ServerRequestInterface $request
     *
     * @return array
     */
    protected function getClientCredentials(ServerRequestInterface $request)
    {
        list($basicAuthUser, $basicAuthPassword) = $this->getBasicAuthCredentials($request);

        $clientId = $this->getRequestParameter('client_id', $request, $basicAuthUser);

        if (\is_null($clientId)) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        $clientSecret = $this->getRequestParameter('client_secret', $request, $basicAuthPassword);

        return [$clientId, $clientSecret];
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

        return $requestParameters[$parameter] ?? $default;
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
        if (\strpos($header, 'Basic ') !== 0) {
            return [null, null];
        }

        if (!($decoded = \base64_decode(\substr($header, 6)))) {
            return [null, null];
        }

        if (\strpos($decoded, ':') === false) {
            return [null, null]; // HTTP Basic header without colon isn't valid
        }

        return \explode(':', $decoded, 2);
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
}
