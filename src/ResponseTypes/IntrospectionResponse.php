<?php

namespace League\OAuth2\Server\ResponseTypes;

use Lcobucci\JWT\Token;
use Psr\Http\Message\ResponseInterface;

class IntrospectionResponse extends AbstractResponseType
{
    /**
     * @var Token
     */
    protected $token;

    /**
     * Set the token against the response
     *
     * @param Token
     */
    public function setToken(Token $token)
    {
        $this->token = $token;
    }

    /**
     * Extract the introspection params from the token
     */
    public function getValidIntrospectionParams()
    {
        $token = $this->token;

        if (!$token){
            return [];
        }

        return [
            'active' => true,
            'token_type' => 'access_token',
            'scope' => $token->getClaim('scopes', ''),
            'client_id' => $token->getClaim('aud'),
            'exp' => $token->getClaim('exp'),
            'iat' => $token->getClaim('iat'),
            'sub' => $token->getClaim('sub'),
            'jti' => $token->getClaim('jti'),
        ];
    }

    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        if ($this->token) {
            $responseParams = $this->getValidIntrospectionParams();
            $responseParams = array_merge($this->getExtraParams(), $responseParams);
        }
        else {
            $responseParams = [
                'active' => false,
            ];
        }

        $response = $response
                ->withStatus(200)
                ->withHeader('pragma', 'no-cache')
                ->withHeader('cache-control', 'no-store')
                ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write(json_encode($responseParams));

        return $response;
    }

    /**
     * Add custom fields to your Introspection response here, then set your introspection
     * reponse in AuthorizationServer::setIntrospectionResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @return array
     */
    protected function getExtraParams()
    {
        return [];
    }
}
