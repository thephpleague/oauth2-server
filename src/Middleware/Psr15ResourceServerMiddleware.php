<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Middleware;

use Exception;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class Psr15ResourceServerMiddleware implements MiddlewareInterface
{
    /**
     * @var ResourceServer
     */
    private $server;

    /**
     * @var ResponseFactoryInterface
     */
    private $responseFactory;

    /**
     * @param ResourceServer           $server
     * @param ResponseFactoryInterface $responseFactory
     */
    public function __construct(ResourceServer $server, ResponseFactoryInterface $responseFactory)
    {
        $this->server = $server;
        $this->responseFactory = $responseFactory;
    }

    /**
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * 
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $request = $this->server->validateAuthenticatedRequest($request);
        } catch (OAuthServerException $exception) {
            return $exception->generateHttpResponse($this->responseFactory->createResponse());
            // @codeCoverageIgnoreStart
        } catch (Exception $exception) {
            return (new OAuthServerException($exception->getMessage(), 0, 'unknown_error', 500))
                            ->generateHttpResponse($this->responseFactory->createResponse());
            // @codeCoverageIgnoreEnd
        }

        // Pass the request on to the next responder in the chain
        return $handler->handle($request);
    }
}
