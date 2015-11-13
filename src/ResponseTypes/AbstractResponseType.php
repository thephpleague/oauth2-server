<?php
/**
 * OAuth 2.0 Abstract Response Type
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;

abstract class AbstractResponseType implements ResponseTypeInterface
{
    /**
     * Response array for JSON serialization
     *
     * @var array
     */
    protected $response = [];

    /**
     * @var \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    protected $accessToken;

    /**
     * {@inheritdoc}
     */
    public function setParam($key, $value)
    {
        $this->response[$key] = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function getParam($key)
    {
        return isset($this->response[$key]) ? $this->response[$key] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken)
    {
        $this->accessToken = $accessToken;
    }
}
