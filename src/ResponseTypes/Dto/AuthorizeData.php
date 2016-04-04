<?php

namespace League\OAuth2\Server\ResponseTypes\Dto;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;

/**
 * Class AuthorizeData
 *
 * @package League\OAuth2\Server\TemplateRenderer\Dto
 */
final class AuthorizeData
{
    /**
     * @var ClientEntityInterface
     */
    private $client;
    /**
     * @var string
     */
    private $postbackUri;
    /**
     * @var array
     */
    private $queryParams;
    /**
     * @var array
     */
    private $scopes;
    /**
     * @var string
     */
    private $encryptedUserId;

    /**
     * @param ClientEntityInterface $client
     * @param array                 $scopes
     * @param string                $postbackUri
     * @param array                 $queryParams
     * @param string                $encryptedUserId
     */
    public function __construct(ClientEntityInterface $client, array $scopes, $postbackUri, array $queryParams, $encryptedUserId)
    {
        $this->client = $client;
        $this->postbackUri = $postbackUri;
        $this->queryParams = $queryParams;
        $this->scopes = $scopes;
        $this->encryptedUserId = $encryptedUserId;
    }

    /**
     * @return ClientEntityInterface
     */
    public function getClient()
    {
        return $this->client;
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

    /**
     * @return array
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * @return string
     */
    public function getEncryptedUserId()
    {
        return $this->encryptedUserId;
    }
}
