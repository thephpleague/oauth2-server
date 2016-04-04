<?php

namespace League\OAuth2\Server\ResponseTypes\Dto;

final class EncryptedRefreshToken
{
    /**
     * @var string
     */
    private $refreshToken;

    /**
     * @param string $refreshToken
     */
    public function __construct($refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->refreshToken;
    }
}
