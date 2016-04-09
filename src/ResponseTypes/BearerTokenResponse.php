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
namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\Dto\EncryptedRefreshToken;
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
     * @var AccessTokenConverterInterface
     */
    private $accessTokenConverter;

    /**
     * @param AccessTokenConverterInterface $accessTokenConverter
     * @param AccessTokenEntityInterface    $accessToken
     * @param EncryptedRefreshToken         $refreshToken
     */
    public function __construct(
        AccessTokenConverterInterface $accessTokenConverter,
        AccessTokenEntityInterface $accessToken,
        EncryptedRefreshToken $refreshToken = null
    ) {
        $this->accessTokenConverter = $accessTokenConverter;
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
    }

    /**
     * {@inheritdoc}
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $expireDateTime = $this->accessToken->getExpiryDateTime()->getTimestamp();

        $responseParams = [
            'token_type'   => 'Bearer',
            'expires_in'   => $expireDateTime - (new \DateTime())->getTimestamp(),
            'access_token' => $this->accessTokenConverter->convert($this->accessToken),
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
