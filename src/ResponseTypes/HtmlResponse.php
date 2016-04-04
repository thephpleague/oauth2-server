<?php

namespace League\OAuth2\Server\ResponseTypes;

use Psr\Http\Message\ResponseInterface;

class HtmlResponse implements ResponseTypeInterface
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
     * @param int    $statusCode
     * @param array  $headers
     */
    public function __construct($html, $statusCode = 200, array $headers = [])
    {
        $this->html = $html;
        $this->headers = $headers;
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
}
