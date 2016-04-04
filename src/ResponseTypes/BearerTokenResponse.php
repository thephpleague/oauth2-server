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

use League\OAuth2\Server\AccessTokenToJwtConverter;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;
use Psr\Http\Message\ResponseInterface;

class BearerTokenResponse implements ResponseTypeInterface
{
    use CryptTrait;
    /**
     * @var \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    protected $accessToken;

    /**
     * @var \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface
     */
    protected $refreshToken;
    /**
     * @var AccessTokenToJwtConverter
     */
    private $accessTokenToJwtConverter;

    /**
     * {@inheritdoc}
     */
    public function __construct(
        $privateKeyPath,
        $publicKeyPath,
        AccessTokenToJwtConverter $accessTokenToJwtConverter,
        AccessTokenEntityInterface $accessToken,
        RefreshTokenEntityInterface $refreshToken = null
    ) {
        $this->setPrivateKeyPath($privateKeyPath);
        $this->setPublicKeyPath($publicKeyPath);
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

        $jwtAccessToken = $this->accessTokenToJwtConverter->convert($this->accessToken);

        $responseParams = [
            'token_type'   => 'Bearer',
            'expires_in'   => $expireDateTime - (new \DateTime())->getTimestamp(),
            'access_token' => (string) $jwtAccessToken,
        ];

        if ($this->refreshToken instanceof RefreshTokenEntityInterface) {
            $refreshToken = $this->encrypt(
                json_encode(
                    [
                        'client_id'        => $this->accessToken->getClient()->getIdentifier(),
                        'refresh_token_id' => $this->refreshToken->getIdentifier(),
                        'access_token_id'  => $this->accessToken->getIdentifier(),
                        'scopes'           => $this->accessToken->getScopes(),
                        'user_id'          => $this->accessToken->getUserIdentifier(),
                        'expire_time'      => $expireDateTime,
                    ]
                )
            );

            $responseParams['refresh_token'] = $refreshToken;
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
