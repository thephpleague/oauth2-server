<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Middleware;

use League\OAuth2\Server\HttpMessageConverter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Request;
use Zend\Diactoros\Response;

class SymfonyResourceServerMiddleware extends Psr7ResourceServerMiddleware
{
    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param callable                                  $next
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function handle(Request $request, callable $next)
    {
        return $this->__invoke($request, $next);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param callable                                  $next
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(Request $request, callable $next)
    {
        $psr7request = HttpMessageConverter::convertSymfonyRequestToPsr7($request);
        $psr7response = new Response();

        return parent::__invoke(
            $psr7request,
            $psr7response,
            function (ServerRequestInterface $psr7request, ResponseInterface $psr7response) use ($next) {
                return $next(
                    HttpMessageConverter::convertPsr7RequestToSymfony($psr7request),
                    HttpMessageConverter::convertPsr7ResponseToSymfony($psr7response)
                );
            }
        );
    }
}
