<?php

namespace League\OAuth2\Server\Entities\Traits;

trait AuthCodeTrait
{
    /**
     * @var null|string
     */
    protected $redirectUri;

    /**
     * @return string
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * @param string $uri
     */
    public function setRedirectUri($uri)
    {
        $this->redirectUri = $uri;
    }
}
