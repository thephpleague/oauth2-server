<?php

namespace League\OAuth2\Server\ResponseTypes\Introspection;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class AbstractResponseType implements ResponseTypeInterface
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
    public function setValidity(bool $bool): void
    {
        $this->valid = $bool;
    }

    /**
     * Set the request.
     *
     * @param ServerRequestInterface $request
     */
    public function setRequest(ServerRequestInterface $request): void
    {
        $this->request = $request;
    }

    /**
     * Return the valid introspection parameters.
     *
     * @return array
     */
    protected function validIntrospectionResponse(): array
    {
        $responseParams = [
            'active' => true,
        ];

        return \array_merge($this->getExtraParams(), $responseParams);
    }

    /**
     * Return the invalid introspection parameters.
     *
     * @return array
     */
    protected function invalidIntrospectionResponse(): array
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
    public function getIntrospectionResponseParams(): array
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
    protected function isValid(): bool
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
    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        $responseParams = $this->getIntrospectionResponseParams();

        $response = $response
                ->withStatus(200)
                ->withHeader('pragma', 'no-cache')
                ->withHeader('cache-control', 'no-store')
                ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write(\json_encode($responseParams));

        return $response;
    }

    /**
     * Add custom fields to your Introspection response here, then add your introspection
     * response to IntrospectionServer constructor to pull in your version of
     * this class rather than the default.
     *
     * @return array
     */
    protected function getExtraParams(): array
    {
        return [];
    }
}
