<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Middleware;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationServerMiddleware
{
    /**
     * @var \League\OAuth2\Server\AuthorizationServer
     */
    private $server;

    /**
     * AuthorizationServerMiddleware constructor.
     *
     * @param \League\OAuth2\Server\AuthorizationServer $server
     */
    public function __construct(AuthorizationServer $server)
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
            $response = $this->server->respondToAccessTokenRequest($request, $response);
        } catch (OAuthServerException $exception) {
            return $exception->generateHttpResponse($response);
            // @codeCoverageIgnoreStart
        } catch (\Exception $exception) {
            $response->getBody()->write($exception->getMessage());

            return $response->withStatus(500);
            // @codeCoverageIgnoreEnd
        }

        // Pass the request and response on to the next responder in the chain
        return $next($request, $response);
    }
}
