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
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;
use League\OAuth2\Server\Utils\KeyCrypt;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;

class BearerTokenResponse extends AbstractResponseType
{
    /**
     * {@inheritdoc}
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $jwtAccessToken = (new Builder())
            ->setAudience($this->accessToken->getClient()->getIdentifier())
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
            $refreshToken = KeyCrypt::encrypt(
                json_encode(
                    [
                        'client_id'        => $this->accessToken->getClient()->getIdentifier(),
                        'refresh_token_id' => $this->refreshToken->getIdentifier(),
                        'access_token_id'  => $this->accessToken->getIdentifier(),
                        'scopes'           => $this->accessToken->getScopes(),
                        'user_id'          => $this->accessToken->getUserIdentifier(),
                        'expire_time'      => $this->refreshToken->getExpiryDateTime()->getTimestamp(),
                    ]
                ),
                $this->pathToPrivateKey
            );

            $responseParams['refresh_token'] = $refreshToken;
        }

        $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json;charset=UTF-8')
            ->getBody()->write(json_encode($responseParams));

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function determineAccessTokenInHeader(ServerRequestInterface $request)
    {
        $header = $request->getHeader('authorization');
        $jwt = trim(preg_replace('/^(?:\s+)?Bearer\s/', '', $header));

        try {
            // Attempt to parse and validate the JWT
            $token = (new Parser())->parse($jwt);
            if ($token->verify(new Sha256(), $this->pathToPublicKey) === false) {
                return $request;
            }

            // Check if token has been revoked
            if ($this->accessTokenRepository->isAccessTokenRevoked($token->getClaim('jwt'))) {
                return $request;
            }

            // Return the request with additional attributes
            return $request->withAttribute('oauth_access_token', $token->getClaim('jti'))
                ->withAttribute('oauth_client_id', $token->getClaim('aud'))
                ->withAttribute('oauth_user_id', $token->getClaim('sub'))
                ->withAttribute('oauth_scopes', $token->getClaim('scopes'));
        } catch (\InvalidArgumentException $e) {
            // JWT couldn't be parsed so return the request as is
            return $request;
        }
    }
}
