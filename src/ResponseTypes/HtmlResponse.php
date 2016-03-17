<?php

namespace League\OAuth2\Server\ResponseTypes;

use Psr\Http\Message\ResponseInterface;

class HtmlResponse extends AbstractResponseType
{
    /**
     * @var string
     */
    private $html = '';

    /**
     * @var int
     */
    private $statusCode = 200;

    /**
     * @var array
     */
    private $headers = [];

    /**
     * @param string $html
     */
    public function setHtml($html)
    {
        $this->html = $html;
    }

    /**
     * @param int $statusCode
     */
    public function setStatusCode($statusCode = 200)
    {
        $this->statusCode = $statusCode;
    }

    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $response->getBody()->write($this->html);

        foreach ($this->headers as $key => $value) {
            $response = $response->withHeader($key, $value);
        }

        return $response
            ->withStatus($this->statusCode)
            ->withHeader('content-type', 'text/html');
    }

    /**
     * @param string $key
     * @param string $value
     */
    public function setHeader($key, $value)
    {
        $this->headers[$key] = $value;
    }
}
