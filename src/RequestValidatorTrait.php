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
     * @return EmitterInterface
     */
    abstract public function getEmitter();

    /**
     * @return ClientRepositoryInterface
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
    public function validateClient(ServerRequestInterface $request)
    {
        list($basicAuthUser, $basicAuthPassword) = $this->getBasicAuthCredentials($request);

        $clientId = $this->getRequestParameter('client_id', $request, $basicAuthUser);
        if ($clientId === null) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        // If the client is confidential require the client secret
        $clientSecret = $this->getRequestParameter('client_secret', $request, $basicAuthPassword);

        $client = $this->getClientRepository()->getClientEntity(
            $clientId,
            $this->getIdentifier(),
            $clientSecret,
            true
        );

        if ($client instanceof ClientEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient();
        }

        $redirectUri = $this->getRequestParameter('redirect_uri', $request, null);

        if ($redirectUri !== null) {
            $this->validateRedirectUri($redirectUri, $client, $request);
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
    public function validateRedirectUri(
        $redirectUri,
        ClientEntityInterface $client,
        ServerRequestInterface $request
    ) {
        if (\is_string($client->getRedirectUri())
            && (strcmp($client->getRedirectUri(), $redirectUri) !== 0)
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient();
        } elseif (\is_array($client->getRedirectUri())
            && \in_array($redirectUri, $client->getRedirectUri(), true) === false
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient();
        }
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

        return isset($requestParameters[$parameter]) ? $requestParameters[$parameter] : $default;
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
    public function getBasicAuthCredentials(ServerRequestInterface $request)
    {
        if (!$request->hasHeader('Authorization')) {
            return [null, null];
        }

        $header = $request->getHeader('Authorization')[0];
        if (strpos($header, 'Basic ') !== 0) {
            return [null, null];
        }

        if (!($decoded = base64_decode(substr($header, 6)))) {
            return [null, null];
        }

        if (strpos($decoded, ':') === false) {
            return [null, null]; // HTTP Basic header without colon isn't valid
        }

        return explode(':', $decoded, 2);
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
