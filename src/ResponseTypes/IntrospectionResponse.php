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
     * @return array
     */
    private function validTokenResponse()
    {
        $responseParams = [
            'active' => true,
            'token_type' => 'access_token',
            'scope' => $this->token->getClaim('scopes', ''),
            'client_id' => $this->token->getClaim('aud'),
            'exp' => $this->token->getClaim('exp'),
            'iat' => $this->token->getClaim('iat'),
            'sub' => $this->token->getClaim('sub'),
            'jti' => $this->token->getClaim('jti'),
        ];

        return array_merge($this->getExtraParams(), $responseParams);
    }

    /**
     * @return array
     */
    private function invalidTokenResponse()
    {
        return [
            'active' => false,
        ];
    }

    /**
     * Extract the introspection params from the token
     *
     * @return array
     */
    public function getIntrospectionParams()
    {
        return $this->hasToken() ?
            $this->validTokenResponse() :
            $this->invalidTokenResponse();
    }

    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $responseParams = $this->getIntrospectionParams();

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
