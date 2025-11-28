<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Handlers;

use League\OAuth2\Server\ResponseTypes\IntrospectionResponse;
use League\OAuth2\Server\ResponseTypes\IntrospectionResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenIntrospectionHandler extends AbstractTokenHandler
{
    private ?IntrospectionResponseTypeInterface $responseType = null;

    protected function getResponseType(): IntrospectionResponseTypeInterface
    {
        return $this->responseType === null ? new IntrospectionResponse() : clone $this->responseType;
    }

    public function setResponseType(IntrospectionResponseTypeInterface $responseType): void
    {
        $this->responseType = $responseType;
    }

    public function respondToRequest(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $client = $this->validateClient($request);
        [$tokenType, $tokenData] = $this->validateToken($request, $client);

        $responseType = $this->getResponseType();

        if ($tokenType === null || $tokenData === null) {
            $responseType->setActive(false);
        } else {
            $responseType->setActive(true);
            $responseType->setTokenType($tokenType);
            $responseType->setTokenData($tokenData);
        }

        return $responseType->generateHttpResponse($response);
    }
}
