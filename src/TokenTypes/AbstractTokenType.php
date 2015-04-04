<?php
/**
 * OAuth 2.0 Abstract Token Type
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\TokenTypes;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;

abstract class AbstractTokenType implements TokenTypeInterface
{
    /**
     * Response array
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
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessToken
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken)
    {
        $this->accessToken = $accessToken;
    }
}
