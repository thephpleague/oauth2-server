<?php

namespace League\OAuth2\Server\Middleware;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\DeviceAuthorizationRequestRepository;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class DeviceGrantMiddleware implements MiddlewareInterface
{
    private $deviceAuthorizationRequestRepository;
    private $responseFactory;

    public function __construct(
        DeviceAuthorizationRequestRepository $deviceAuthorizationRequestRepository,
        ResponseFactoryInterface $responseFactory
    ) {
        $this->deviceAuthorizationRequestRepository = $deviceAuthorizationRequestRepository;
        $this->responseFactory = $responseFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $queryParameters = $request->getQueryParams();
        $deviceCode = $queryParameters['device_code'];

        // Get the last timestamp this client requested an access code
        $lastRequestTimeStamp = $this->deviceAuthorizationRequestRepository->getLast($deviceCode);

        // If the request is within the last 5 seconds, issue a slowdown notification
        if ($lastRequestTimeStamp + 5 > \time()) {
            return OAuthServerException::slowDown()->generateHttpResponse($this->responseFactory->createResponse());
        }

        return $handler->handle($request);
    }
}
