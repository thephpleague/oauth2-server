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
     * @param Token $token
     */
    public function setToken(Token $token)
    {
        $this->token = $token;
    }

    private function hasToken()
    {
        return $this->token !== null;
    }
    /**
     * Extract the introspection params from the token
     */
    public function getIntrospectionParams()
    {
        if (!$this->hasToken()) {
            return [
                'active' => false,
            ];
        }

        return [
            'active' => true,
            'token_type' => 'access_token',
            'scope' => $this->token->getClaim('scopes', ''),
            'client_id' => $this->token->getClaim('aud'),
            'exp' => $this->token->getClaim('exp'),
            'iat' => $this->token->getClaim('iat'),
            'sub' => $this->token->getClaim('sub'),
            'jti' => $this->token->getClaim('jti'),
        ];
    }

    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $responseParams = $this->getIntrospectionParams();

        if ($this->hasToken()) {
            $responseParams = array_merge($this->getExtraParams(), $responseParams);
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
