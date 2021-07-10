<?php

namespace League\OAuth2\Server\IntrospectionValidators;

use Psr\Http\Message\ServerRequestInterface;

interface IntrospectionValidatorInterface
{
    /**
     * Determine wether the introspection request is valid.
     *
     * @param ServerRequestInterface $request
     *
     * @return bool
     */
    public function validateIntrospection(ServerRequestInterface $request);
}
