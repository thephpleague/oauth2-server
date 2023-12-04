<?php

namespace League\OAuth2\Server\IntrospectionValidators;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;

interface IntrospectionValidatorInterface
{
    /**
     * Determine whether the introspection request is valid.
     *
     * @param ServerRequestInterface $request
     *
     * @throws OAuthServerException
     *
     * @return bool
     */
    public function validateIntrospection(ServerRequestInterface $request): bool;
}
