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
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class AbstractResponseType implements ResponseTypeInterface
{
    /**
     * @var string
     */
    protected $pathToPrivateKey;

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
     * @param string                                                            $pathToPrivateKey
     * @param string                                                            $pathToPublicKey
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function __construct(
        $pathToPrivateKey,
        $pathToPublicKey,
        AccessTokenRepositoryInterface $accessTokenRepository
    ) {
        $this->pathToPrivateKey = $pathToPrivateKey;
        $this->pathToPublicKey = $pathToPublicKey;
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
     * {@inheritdoc}
     */
    public function setRefreshToken(RefreshTokenEntityInterface $refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    /**
     * {@inheritdoc}
     */
    public function validateAccessToken(ServerRequestInterface $request)
    {
        if ($request->hasHeader('authorization') === false) {
            throw OAuthServerException::accessDenied('Missing "Authorization" header');
        }

        return $request;
    }
}
