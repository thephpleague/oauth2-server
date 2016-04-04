<?php
namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\Dto\AuthorizeData;
use League\OAuth2\Server\ResponseTypes\Dto\CodeData;
use League\OAuth2\Server\ResponseTypes\Dto\EncryptedRefreshToken;
use League\OAuth2\Server\ResponseTypes\Dto\LoginData;

interface ResponseFactoryInterface
{
    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     *
     * @return ResponseTypeInterface
     */
    public function newAccessTokenResponse(AccessTokenEntityInterface $accessTokenEntity);

    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     * @param EncryptedRefreshToken      $encryptedRefreshToken
     *
     * @return ResponseTypeInterface
     */
    public function newRefreshTokenResponse(
        AccessTokenEntityInterface $accessTokenEntity,
        EncryptedRefreshToken $encryptedRefreshToken
    );

    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     * @param string                     $redirectUri
     * @param string                     $state
     *
     * @return ResponseTypeInterface
     */
    public function newAccessTokenRedirectResponse(
        AccessTokenEntityInterface $accessTokenEntity,
        $redirectUri,
        $state
    );

    /**
     * @param LoginData $loginData
     *
     * @return ResponseTypeInterface
     */
    public function newHtmlLoginResponse(LoginData $loginData);

    /**
     * @param AuthorizeData $authorizeData
     *
     * @return ResponseTypeInterface
     */
    public function newHtmlAuthorizeResponse(AuthorizeData $authorizeData);

    /**
     * @param CodeData $authCodeData
     *
     * @return ResponseTypeInterface
     */
    public function newAuthCodeRedirectResponse(CodeData $authCodeData);
}
