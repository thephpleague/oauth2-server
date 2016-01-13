<?php
/**
 * OAuth 2.0 Bearer Token Type
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\ResponseTypes;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;

class BearerTokenResponse extends AbstractResponseType
{
    /**
     * {@inheritdoc}
     */
    public function generateHttpResponse()
    {
        $jwtAccessToken = (new Builder())->setAudience($this->accessToken->getClient()->getIdentifier())
            ->setId($this->accessToken->getIdentifier(), true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration($this->accessToken->getExpiryDateTime()->getTimestamp())
            ->setSubject($this->accessToken->getUserIdentifier())
            ->set('scopes', $this->accessToken->getScopes())
            ->sign(new Sha256(), new Key($this->pathToPrivateKey))
            ->getToken();

        $responseParams = [
            'token_type'   => 'Bearer',
            'expires_in'   => $this->accessToken->getExpiryDateTime()->getTimestamp() - (new \DateTime())->getTimestamp(),
            'access_token' => (string) $jwtAccessToken,
        ];

        if ($this->refreshToken instanceof RefreshTokenEntityInterface) {
            $jwtRefreshToken = (new Builder())->setAudience($this->accessToken->getClient()->getIdentifier())
                ->setId($this->refreshToken->getIdentifier())
                ->setIssuedAt(time())
                ->setNotBefore(time())
                ->setExpiration($this->refreshToken->getExpiryDateTime()->getTimestamp())
                ->set('type', 'refreshToken')
                ->setSubject($this->accessToken->getUserIdentifier())
                ->set('scopes', $this->accessToken->getScopes())
                ->set('accessToken', $this->accessToken->getIdentifier())
                ->sign(new Sha256(), new Key($this->pathToPrivateKey))
                ->getToken();

            $responseParams['refresh_token'] = (string) $jwtRefreshToken;
        }

        $response = new Response(
            'php://memory',
            200,
            [
                'pragma'        => 'no-cache',
                'cache-control' => 'no-store',
                'content-type'  => 'application/json;charset=UTF-8'
            ]
        );
        $response->getBody()->write(json_encode($responseParams));

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function determineAccessTokenInHeader(ServerRequestInterface $request)
    {
        $header = $request->getHeader('authorization');
        $accessToken = trim(preg_replace('/^(?:\s+)?Bearer\s/', '', $header));

        return ($accessToken === 'Bearer') ? '' : $accessToken;
    }
}
