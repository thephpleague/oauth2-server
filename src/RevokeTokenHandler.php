<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

class RevokeTokenHandler implements EmitterAwareInterface
{
    use EmitterAwareTrait, CryptTrait, RequestValidatorTrait;

    /**
     * @var ClientRepositoryInterface
     */
    protected $clientRepository;

    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var RefreshTokenRepositoryInterface
     */
    private $refreshTokenRepository;

    /**
     * @var bool
     */
    private $canRevokeAccessTokens;

    /**
     * @var CryptKey
     */
    protected $publicKey;

    /**
     * New handler instance.
     *
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param CryptKey|string                 $publicKey
     * @param bool                            $canRevokeAccessTokens
     */
    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        $publicKey,
        $canRevokeAccessTokens = true
    ) {
        $this->setRefreshTokenRepository($refreshTokenRepository);

        if ($publicKey instanceof CryptKey === false) {
            $publicKey = new CryptKey($publicKey);
        }
        $this->publicKey = $publicKey;

        $this->canRevokeAccessTokens = $canRevokeAccessTokens;
    }

    /**
     * @return ClientRepositoryInterface
     */
    public function getClientRepository()
    {
        return $this->clientRepository;
    }

    /**
     * @param ClientRepositoryInterface $clientRepository
     */
    public function setClientRepository(ClientRepositoryInterface $clientRepository)
    {
        $this->clientRepository = $clientRepository;
    }

    /**
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository)
    {
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function setRefreshTokenRepository(RefreshTokenRepositoryInterface $refreshTokenRepository)
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    /**
     * Set the public key
     *
     * @param CryptKey $key
     */
    public function setPublicKey(CryptKey $key)
    {
        $this->publicKey = $key;
    }

    /**
     * Return the grant identifier that can be used in matching up requests.
     *
     * @return string
     */
    public function getIdentifier()
    {
        return '';
    }

    /**
     * Return a revoke token response.
     * https://tools.ietf.org/html/rfc7009
     *
     * @param ServerRequestInterface $request
     * @param ResponseTypeInterface  $responseType
     *
     * @throws OAuthServerException
     *
     * @return ResponseTypeInterface
     */
    public function respondToRevokeTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $responseType)
    {
        $token = $this->getRequestParameter('token', $request);
        $hint = $this->getRequestParameter('token_type_hint', $request);

        // Validate request
        $client = $this->validateClient($request);
        $clientId = $client->getIdentifier();

        if (\is_null($token)) {
            return $responseType;
        }

        // Attempt to revoke tokens
        if ($hint === 'refresh_token') {
            if (!$this->revokeRefreshToken($token, $clientId, $request)) {
                $this->revokeAccessToken($token, $clientId, $request);
            }
        } else {
            if (!$this->revokeAccessToken($token, $clientId, $request)) {
                $this->revokeRefreshToken($token, $clientId, $request);
            }
        }

        return $responseType;
    }

    /**
     * @param string $tokenParam
     * @param string $clientId
     *
     * @throws OAuthServerException
     *
     * @return bool true if token was a refresh token
     */
    protected function revokeAccessToken($tokenParam, $clientId, ServerRequestInterface $request)
    {
        $token = null;
        try {
            $token = (new Parser())->parse($tokenParam);

            if ($token->verify(new Sha256(), $this->publicKey->getKeyPath()) === false) {
                return false;
            }
        } catch (Exception $exception) {
            // JWT couldn't be parsed as access token
            return false;
        }

        $clientId = $token->getClaim('aud');
        if ($clientId !== $clientId) {
            throw OAuthServerException::invalidClient($request);
        }

        if (!$this->canRevokeAccessTokens) {
            $errorMessage = 'The authorization server does not support the revocation of the presented token type.';
            throw new OAuthServerException($errorMessage, 2, 'unsupported_token_type', 400);
        }
        $this->accessTokenRepository->revokeAccessToken($token->getClaim('jti'));

        return true;
    }

    /**
     * @param string $tokenParam
     * @param string $clientId
     *
     * @throws OAuthServerException
     *
     * @return bool true if token was a refresh token
     */
    protected function revokeRefreshToken($tokenParam, $clientId, ServerRequestInterface $request)
    {
        $refreshTokenData = null;
        try {
            $refreshToken = $this->decrypt($tokenParam);
            $refreshTokenData = \json_decode($refreshToken, true);
        } catch (Exception $e) {
            // token couldn't be decrypted as refresh token
            return false;
        }

        if ($refreshTokenData['client_id'] !== $clientId) {
            throw OAuthServerException::invalidClient($request);
        }

        $this->refreshTokenRepository->revokeRefreshToken($refreshTokenData['refresh_token_id']);
        if ($this->canRevokeAccessTokens) {
            $this->accessTokenRepository->revokeAccessToken($refreshTokenData['access_token_id']);
        }

        return true;
    }
}
