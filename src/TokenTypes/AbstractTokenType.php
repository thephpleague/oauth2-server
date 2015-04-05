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
use Symfony\Component\HttpFoundation\Response;

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
     * {@inheritdoc}
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function generateHttpResponse()
    {
        return new Response(
            json_encode($this->generateResponse()),
            200,
            [
                'Content-type'  => 'application/json',
                'Cache-Control' => 'no-store',
                'Pragma'        => 'no-cache'
            ]
        );
    }
}
