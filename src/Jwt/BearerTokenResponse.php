<?php
/**
 * OAuth 2.0 Bearer Token Type.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Jwt;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\Dto\EncryptedRefreshToken;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;

class BearerTokenResponse implements ResponseTypeInterface
{
    /**
     * @var \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    protected $accessToken;
    /**
     * @var EncryptedRefreshToken
     */
    protected $refreshToken;
    /**
     * @var AccessTokenConverter
     */
    private $accessTokenToJwtConverter;

    /**
     * @param AccessTokenConverterInterface $accessTokenToJwtConverter
     * @param AccessTokenEntityInterface    $accessToken
     * @param EncryptedRefreshToken         $refreshToken
     */
    public function __construct(
        AccessTokenConverterInterface $accessTokenToJwtConverter,
        AccessTokenEntityInterface $accessToken,
        EncryptedRefreshToken $refreshToken = null
    ) {
        $this->accessTokenToJwtConverter = $accessTokenToJwtConverter;
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
    }

    /**
     * {@inheritdoc}
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $expireDateTime = $this->accessToken->getExpiryDateTime()->getTimestamp();

        $jwtAccessToken = $this->accessTokenToJwtConverter->convert($this->accessToken)->getToken();

        $responseParams = [
            'token_type'   => 'Bearer',
            'expires_in'   => $expireDateTime - (new \DateTime())->getTimestamp(),
            'access_token' => (string) $jwtAccessToken,
        ];

        if ($this->refreshToken instanceof EncryptedRefreshToken) {
            $responseParams['refresh_token'] = (string) $this->refreshToken;
        }

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write(json_encode($responseParams));

        return $response;
    }
}
