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
use InvalidArgumentException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\ClientValidator;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\RequestValidatorTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

class RevokeTokenHandler implements EmitterAwareInterface
{
    use EmitterAwareTrait, CryptTrait, RequestValidatorTrait;

    /**
     * @var ClientValidator
     */
    protected $clientValidator;

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
    )
    {
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
    public function getIdentifier() {
		return null;
	}

   /**
     * Return an revoke token response.
     * https://tools.ietf.org/html/rfc7009
     *
     * @param ServerRequestInterface $request
     * @param ResponseTypeInterface  $response
     *
     * @throws OAuthServerException
     *
     * @return ResponseTypeInterface
     */
    public function respondToRevokeTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $response)
    {
        if ($request->getMethod() !== 'POST') {
            $errorMessage = 'POST method required.';
            throw new OAuthServerException($errorMessage, 3, 'invalid_request', 400);
        }

        $token = $this->getRequestParameter('token', $request);
        $hint = $this->getRequestParameter('token_type_hint', $request);

        // Validate request
        $client = $this->validateClient($request);
        $clientId = $client->getIdentifier();

        if (is_null($token)) {
            return $response;
        }

        // Attempt to read token
        $accessToken = null;
        $refreshToken = null;
        if ($hint === 'access_token') {
            $accessToken = $this->readAsAccessToken($token, $clientId);
        } else if ($hint === 'refresh_token') {
            $refreshToken = $this->readAsRefreshToken($token, $clientId);
        } else {
            $accessToken = $this->readAsAccessToken($token, $clientId);
            if ($accessToken === null) {
                $refreshToken = $this->readAsRefreshToken($token, $clientId);
            }
        }

        // Revoke tokens
        if ($accessToken !== null) {
            if (!$this->canRevokeAccessTokens) {
                $errorMessage = 'The authorization server does not support the revocation of the presented token type';
                throw new OAuthServerException($errorMessage, 2, 'unsupported_token_type', 400);
            }
            $this->accessTokenRepository->revokeAccessToken($accessToken->getClaim('jti'));
        } else if ($refreshToken !== null) {
            $this->refreshTokenRepository->revokeRefreshToken($refreshToken['refresh_token_id']);
            if ($this->canRevokeAccessTokens) {
                $this->accessTokenRepository->revokeAccessToken($refreshToken['access_token_id']);
            }
        }

        return $response;
    }

    /**
     * @param string $tokenParam
     * @param string $clientId
     *
     * @return null|Token
     */
    protected function readAsAccessToken($tokenParam, $clientId) {
        $token = null;
        try {
            $token = (new Parser())->parse($tokenParam);

            if ($token->verify(new Sha256(), $this->publicKey->getKeyPath()) === false) {
                return null;
            }
        } catch (Exception $exception) {
            // JWT couldn't be parsed so ignore
            return null;
        }

        $clientId = $token->getClaim('aud');
        if ($clientId !== $clientId) {
            throw OAuthServerException::invalidClient();
        }
        return $token;
    }

    /**
     * @param string $tokenParam
     * @param string $clientId
     *
     * @return null|array
     */
    protected function readAsRefreshToken($tokenParam, $clientId) {
        $refreshTokenData = null;
        try {
            $refreshToken = $this->decrypt($tokenParam);
            $refreshTokenData = json_decode($refreshToken, true);
        } catch (Exception $e) {
            return null;
            // token couldn't be decrypted so ignore
        }

        if ($refreshTokenData['client_id'] !== $clientId) {
            throw OAuthServerException::invalidClient();
        }
        return $refreshTokenData;
    }
}
