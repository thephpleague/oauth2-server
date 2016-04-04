<?php

namespace League\OAuth2\Server\ResponseTypes\Dto;

/**
 * Class CodeData
 *
 * @package League\OAuth2\Server\ResponseTypes\Dto
 */
final class CodeData
{
    /**
     * @var string
     */
    private $redirectUri;
    /**
     * @var string
     */
    private $state;
    /**
     * @var string
     */
    private $code;

    /**
     * @param string $redirectUri
     * @param string $code
     * @param string $state
     */
    public function __construct($redirectUri, $code, $state)
    {
        $this->redirectUri = $redirectUri;
        $this->state = $state;
        $this->code = $code;
    }

    /**
     * @return string
     */
    public function getCode()
    {
        return $this->code;
    }

    /**
     * @return string
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * @return string
     */
    public function getState()
    {
        return $this->state;
    }
}
