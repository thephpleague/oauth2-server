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
use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;

abstract class AbstractResponseType implements ResponseTypeInterface
{
    /**
     * @var string
     */
    protected $pathToPrivateKey;

    /**
     * @var \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    protected $accessToken;

    /**
     * @var \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface
     */
    protected $refreshToken;

    /**
     * @param string $pathToPrivateKey
     */
    public function __construct($pathToPrivateKey)
    {
        $this->pathToPrivateKey = $pathToPrivateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @param \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface $refreshToken
     */
    public function setRefreshToken(RefreshTokenEntityInterface $refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }
}
