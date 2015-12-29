<?php

namespace League\OAuth2\Server\TokenTypes;

use JWT;
use League\OAuth2\Server\Utils\SecureKey;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class JsonWebTokenType extends AbstractTokenType
{
    /**
     * @var string
     */
    protected static $encryptionKey = 'example-key';

    /**
     * @var string
     */
    protected static $issuer = '';

    /**
     * @var string
     */
    protected static $audience = '';

    /**
     * Set the encryption
     *
     * @param string $key
     */
    public static function setEncryptionKey($key)
    {
        self::$encryptionKey = $key;
    }

    /**
     * @param string $issuer
     */
    public static function setIssuer($issuer)
    {
        self::$issuer = $issuer;
    }

    /**
     * @param string $audience
     */
    public static function setAudience($audience)
    {
        self::$audience = $audience;
    }

    /**
     * Generate a response
     *
     * @return array
     */
    public function generateResponse()
    {
        $return = [
            'access_token' => $this->accessToken->getIdentifier(),
            'token_type'   => 'Bearer',
            'expires_in'   => $this->accessToken->getExpiryDateTime()->getTimestamp() - (new \DateTime())->getTimestamp()
        ];

        if (!is_null($this->getParam('refresh_token'))) {
            $return['refresh_token'] = $this->getParam('refresh_token');
        }

        $return['id_token'] = $this->generateJWT();

        return $return;
    }

    /**
     * Generate an JWT
     * @return string
     */
    public function generateJWT()
    {
        $now = new \DateTime();

        $token = [
            'iss' => self::$issuer,
            'aud' => self::$audience,
            'sub' => $this->accessToken->getOwnerIdentifier(),
            'exp' => $this->accessToken->getExpiryDateTime()->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'jti' => SecureKey::generate()
        ];

        return JWT::encode($token, self::$encryptionKey);
    }

    /**
     * {@inheritdoc}
     */
    public function getResponse(ResponseInterface $response = null)
    {
        if ($response === null) {
            $response = new Response('php://memory');
        }

        return $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json;charset=UTF-8')
            ->write(json_encode($this->generateResponse()));
    }

    /**
     * Determine the access token in the authorization header
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return string
     */
    public function determineAccessTokenInHeader(Request $request)
    {
        // TODO: Implement determineAccessTokenInHeader() method.
    }
}
