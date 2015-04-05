<?php

namespace League\OAuth2\Server\Entities\Interfaces;

interface AuthCodeEntityInterface extends TokenInterface
{
    /**
     * @return string
     */
    public function getRedirectUri();

    /**
     * @param string $uri
     */
    public function setRedirectUri($uri);
}
