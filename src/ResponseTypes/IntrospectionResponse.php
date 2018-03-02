<?php

namespace League\OAuth2\Server\ResponseTypes;

use Psr\Http\Message\ResponseInterface;

class IntrospectionResponse extends AbstractResponseType
{
    /**
     * @var array
     */
    private $introspectionData;

    /**
     * @param array $introspectionData
     */
    public function setIntrospectionData(array $introspectionData)
    {
        $this->introspectionData = $introspectionData;
    }

    /**
     * @return array
     */
    public function getIntrospectionData()
    {
        return $this->introspectionData;
    }

    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $response->getBody()->write(json_encode($this->introspectionData));

        return $response;
    }
}
