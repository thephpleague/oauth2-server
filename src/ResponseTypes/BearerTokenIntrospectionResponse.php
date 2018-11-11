<?php

namespace League\OAuth2\Server\ResponseTypes;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;

class BearerTokenIntrospectionResponse extends IntrospectionResponse
{
    /**
     * Add the token data to the response.
     *
     * @return array
     */
    protected function validIntrospectionResponse()
    {
        $token = $this->getTokenFromRequest();

        $responseParams = [
            'active' => true,
            'token_type' => 'access_token',
            'scope' => $token->getClaim('scopes', ''),
            'client_id' => $token->getClaim('aud'),
            'exp' => $token->getClaim('exp'),
            'iat' => $token->getClaim('iat'),
            'sub' => $token->getClaim('sub'),
            'jti' => $token->getClaim('jti'),
        ];

        return array_merge($this->getExtraParams(), $responseParams);
    }

    /**
     * Gets the token from the request body.
     *
     * @return Token
     */
    protected function getTokenFromRequest()
    {
        $jwt = $this->request->getParsedBody()['token'] ?? null;

        return (new Parser())
            ->parse($jwt);
    }
}
