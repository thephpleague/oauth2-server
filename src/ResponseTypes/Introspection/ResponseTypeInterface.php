<?php

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes\Introspection;

use Psr\Http\Message\ResponseInterface;

interface ResponseTypeInterface
{
    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response): ResponseInterface;
}
