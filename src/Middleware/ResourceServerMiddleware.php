<?php

namespace League\OAuth2\Server\Middleware;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Server;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ResourceServerMiddleware
{
    /**
     * @var \League\OAuth2\Server\Server
     */
    private $server;


    /**
     * ResourceServerMiddleware constructor.
     *
     * @param \League\OAuth2\Server\Server $server
     */
    public function __construct(Server $server)
    {
        $this->server = $server;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     * @param callable                                 $next
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $next)
    {
        if ($request->hasHeader('authorization') === false) {
            $exception = OAuthServerException::accessDenied('Missing authorization header');

            return $exception->generateHttpResponse($response);
        }

        $request = $this->server->getResponseType()->determineAccessTokenInHeader($request);

        if ($request->getAttribute('oauth_access_token') === null) {
            $exception = OAuthServerException::accessDenied('Access token was invalid');

            return $exception->generateHttpResponse($response);
        }

        // Pass the request and response on to the next responder in the chain
        return $next($request, $response);
    }
}
