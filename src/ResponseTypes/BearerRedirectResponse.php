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
use Psr\Http\Message\ResponseInterface;

class BearerRedirectResponse implements ResponseTypeInterface
{
    /**
     * @var string
     */
    private $redirectUri;
    /**
     * @var string
     */
    private $state;
    /**
     * @var \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    protected $accessToken;
    /**
     * @var AccessTokenConverterInterface
     */
    private $accessTokenConverter;

    /**
     * @param AccessTokenConverterInterface $accessTokenToJwtConverter
     * @param AccessTokenEntityInterface    $accessToken
     * @param string                        $redirectUri
     * @param string                        $state
     */
    public function __construct(
        AccessTokenConverterInterface $accessTokenToJwtConverter,
        AccessTokenEntityInterface $accessToken,
        $redirectUri,
        $state
    ) {
        $this->redirectUri = $redirectUri;
        $this->state = $state;
        $this->accessToken = $accessToken;
        $this->accessTokenConverter = $accessTokenToJwtConverter;
    }

    /**
     * {@inheritdoc}
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $redirectPayload = [];

        if ($this->state !== null) {
            $redirectPayload['state'] = $this->state;
        }

        $redirectPayload['access_token'] = $this->accessTokenConverter->convert($this->accessToken);
        $redirectPayload['token_type'] = 'Bearer';
        $redirectPayload['expires_in'] = time() - $this->accessToken->getExpiryDateTime()->getTimestamp();

        $uri = $this->makeRedirectUri(
            $this->redirectUri,
            $redirectPayload,
            '#'
        );

        return $response->withStatus(302)->withHeader('location', $uri);
    }

    /**
     * @param string $uri
     * @param array  $params
     * @param string $queryDelimiter
     *
     * @return string
     */
    private function makeRedirectUri($uri, $params = [], $queryDelimiter = '?')
    {
        $uri .= (strstr($uri, $queryDelimiter) === false) ? $queryDelimiter : '&';

        return $uri . http_build_query($params);
    }
}
