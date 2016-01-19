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
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

abstract class AbstractResponseType implements ResponseTypeInterface
{
    /**
     * @var string
     */
    protected $pathToPrivateKey;

    /**
     * @var string
     */
    protected $privateKeyPassphrase;

    /**
     * @var string
     */
    protected $pathToPublicKey;

    /**
     * @var \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    protected $accessToken;

    /**
     * @var \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface
     */
    protected $refreshToken;

    /**
     * @var \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface
     */
    protected $accessTokenRepository;

    /**
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface $accessTokenRepository
     * @param string                                                            $pathToPublicKey
     * @param string                                                            $pathToPrivateKey
     * @param string                                                            $privateKeyPassphrase
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        $pathToPublicKey,
        $pathToPrivateKey,
        $privateKeyPassphrase = ''
    ) {
        $this->pathToPublicKey = $pathToPublicKey;
        $this->pathToPrivateKey = $pathToPrivateKey;
        $this->privateKeyPassphrase = $privateKeyPassphrase;
        $this->accessTokenRepository = $accessTokenRepository;
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
