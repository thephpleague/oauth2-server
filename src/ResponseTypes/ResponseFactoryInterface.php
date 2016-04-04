<?php
namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;

interface ResponseFactoryInterface
{
    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     *
     * @return ResponseTypeInterface
     */
    public function newAccessTokenResponse(AccessTokenEntityInterface $accessTokenEntity);

    /**
     * @param AccessTokenEntityInterface  $accessTokenEntity
     * @param RefreshTokenEntityInterface $refreshTokenEntity
     *
     * @return ResponseTypeInterface
     */
    public function newAccessRefreshTokenResponse(
        AccessTokenEntityInterface $accessTokenEntity,
        RefreshTokenEntityInterface $refreshTokenEntity
    );

    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     * @param $redirectUri
     * @param $state
     *
     * @return ResponseTypeInterface
     */
    public function newAccessTokenRedirectResponse(AccessTokenEntityInterface $accessTokenEntity, $redirectUri, $state);

    /**
     * @param string $html
     * @param int    $statusCode
     * @param array  $headers
     *
     * @return ResponseTypeInterface
     */
    public function newHtmlResponse($html, $statusCode = 200, array $headers = []);

    /**
     * @param $redirectUri
     *
     * @return ResponseTypeInterface
     */
    public function newRedirectResponse($redirectUri);
}
