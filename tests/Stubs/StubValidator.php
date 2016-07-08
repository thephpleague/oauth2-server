<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use Psr\Http\Message\ServerRequestInterface;

class StubValidator implements AuthorizationValidatorInterface
{
    /**
     * @param ServerRequestInterface $request
     *
     * @return ServerRequestInterface
     */
    public function validateAuthorization(ServerRequestInterface $request)
    {
        return $request->withAttribute('validated', true);
    }
}
