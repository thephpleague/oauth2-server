<?php

namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\ClaimSetInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A simple user info response for the ResourceServer class
 *
 * @author Marc Riemer <mail@marcriemer.de>
 */
class UserInfoResponse extends AbstractResponseType
{
    public function __construct(
        protected ClaimSetInterface $claimSet
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write(\json_encode($this->claimSet->getClaims()));

        return $response;
    }
}
