<?php

namespace League\OAuth2\Server\Middleware;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Server;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthenticationServerMiddleware
{
    /**
     * @var \League\OAuth2\Server\Server
     */
    private $server;

    /**
     * AuthenticationServerMiddleware constructor.
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
        try {
            $response = $server->respondToRequest($request, $response);
        } catch (OAuthServerException $exception) {
            return $exception->generateHttpResponse($response);
        } catch (\Exception $exception) {
            return $response->withStatus(500)->write($exception->getMessage());
        }

        if (in_array($response->getStatusCode(), [400, 401, 500])) {
            return $response;
        }

        // Pass the request and response on to the next responder in the chain
        return $next($request, $response);
    }
}
