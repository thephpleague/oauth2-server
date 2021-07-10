<?php

namespace League\OAuth2\Server\ResponseTypes;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class IntrospectionResponse extends AbstractResponseType
{
    /**
     * @var bool
     */
    protected $valid = false;

    /**
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * Set the validity of the response.
     *
     * @param bool $bool
     */
    public function setValidity(bool $bool)
    {
        $this->valid = $bool;
    }

    /**
     * Set the request.
     *
     * @param ServerRequestInterface $request
     */
    public function setRequest(ServerRequestInterface $request)
    {
        $this->request = $request;
    }

    /**
     * Return the valid introspection parameters.
     *
     * @return array
     */
    protected function validIntrospectionResponse()
    {
        $responseParams = [
            'active' => true,
        ];

        return array_merge($this->getExtraParams(), $responseParams);
    }

    /**
     * Return the invalid introspection parameters.
     *
     * @return array
     */
    protected function invalidIntrospectionResponse()
    {
        return [
            'active' => false,
        ];
    }

    /**
     * Extract the introspection response.
     *
     * @return array
     */
    public function getIntrospectionResponseParams()
    {
        return $this->isValid() ?
            $this->validIntrospectionResponse() :
            $this->invalidIntrospectionResponse();
    }

    /**
     * Check if the response is valid.
     *
     * @return bool
     */
    protected function isValid()
    {
        return $this->valid === true;
    }

    /**
     * Generate a HTTP response.
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $responseParams = $this->getIntrospectionResponseParams();

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
