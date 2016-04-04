<?php

namespace League\OAuth2\Server\ResponseTypes\Dto;

/**
 * Class LoginData
 *
 * @package League\OAuth2\Server\ResponseTypes\Dto
 */
final class LoginData
{
    /**
     * @var string
     */
    private $error;
    /**
     * @var string
     */
    private $postbackUri;
    /**
     * @var array
     */
    private $queryParams;

    /**
     * @param string $error
     * @param string $postbackUri
     * @param array  $queryParams
     */
    public function __construct($error, $postbackUri, array $queryParams)
    {
        $this->error = $error;
        $this->postbackUri = $postbackUri;
        $this->queryParams = $queryParams;
    }

    /**
     * @return string
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * @return string
     */
    public function getPostbackUri()
    {
        return $this->postbackUri;
    }

    /**
     * @return array
     */
    public function getQueryParams()
    {
        return $this->queryParams;
    }
}
