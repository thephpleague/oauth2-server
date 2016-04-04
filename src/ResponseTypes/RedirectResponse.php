<?php

namespace League\OAuth2\Server\ResponseTypes;

use Psr\Http\Message\ResponseInterface;

class RedirectResponse implements ResponseTypeInterface
{
    /**
     * @var string
     */
    private $redirectUri;

    /**
     * @param string $redirectUri
     */
    public function __construct($redirectUri)
    {
        $this->redirectUri = $redirectUri;
    }

    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        return $response->withStatus(302)->withHeader('location', $this->redirectUri);
    }
}
