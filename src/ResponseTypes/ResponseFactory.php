<?php
namespace League\OAuth2\Server\ResponseTypes;

use Lcobucci\JWT\Builder;
use League\OAuth2\Server\AccessTokenToJwtConverter;
use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;

final class ResponseFactory implements ResponseFactoryInterface
{
    /**
     * @var
     */
    private $privateKeyPath;
    /**
     * @var
     */
    private $publicKeyPath;

    /**
     * @param $privateKeyPath
     * @param $publicKeyPath
     */
    public function __construct($privateKeyPath, $publicKeyPath)
    {
        $this->privateKeyPath = $privateKeyPath;
        $this->publicKeyPath = $publicKeyPath;
        $this->jwtConverter = new AccessTokenToJwtConverter(new Builder(), $privateKeyPath);
    }

    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     *
     * @return ResponseTypeInterface
     */
    public function newAccessTokenResponse(AccessTokenEntityInterface $accessTokenEntity)
    {
        return new BearerTokenResponse(
            $this->privateKeyPath,
            $this->publicKeyPath,
            $this->jwtConverter,
            $accessTokenEntity
        );
    }

    /**
     * @param AccessTokenEntityInterface  $accessTokenEntity
     * @param RefreshTokenEntityInterface $refreshTokenEntity
     *
     * @return ResponseTypeInterface
     */
    public function newAccessRefreshTokenResponse(
        AccessTokenEntityInterface $accessTokenEntity,
        RefreshTokenEntityInterface $refreshTokenEntity
    ) {
        return new BearerTokenResponse(
            $this->privateKeyPath,
            $this->publicKeyPath,
            $this->jwtConverter,
            $accessTokenEntity,
            $refreshTokenEntity
        );
    }

    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     * @param $redirectUri
     * @param $state
     *
     * @return ResponseTypeInterface
     */
    public function newAccessTokenRedirectResponse(AccessTokenEntityInterface $accessTokenEntity, $redirectUri, $state)
    {
        return new BearerRedirectResponse(
            $this->jwtConverter,
            $accessTokenEntity,
            $redirectUri,
            $state
        );
    }

    /**
     * @param string $html
     * @param int    $statusCode
     * @param array  $headers
     *
     * @return ResponseTypeInterface
     */
    public function newHtmlResponse($html, $statusCode = 200, array $headers = [])
    {
        return new HtmlResponse($html, $statusCode, $headers);
    }

    /**
     * @param $redirectUri
     *
     * @return ResponseTypeInterface
     */
    public function newRedirectResponse($redirectUri)
    {
        return new RedirectResponse($redirectUri);
    }
}
