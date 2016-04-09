<?php
namespace League\OAuth2\Server;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\AccessTokenConverterInterface;
use League\OAuth2\Server\ResponseTypes\BearerRedirectResponse;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\Dto\AuthorizeData;
use League\OAuth2\Server\ResponseTypes\Dto\CodeData;
use League\OAuth2\Server\ResponseTypes\Dto\EncryptedRefreshToken;
use League\OAuth2\Server\ResponseTypes\Dto\LoginData;
use League\OAuth2\Server\ResponseTypes\HtmlResponse;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\TemplateRenderer\RendererInterface;

final class ResponseFactory implements ResponseFactoryInterface
{
    /**
     * @var AccessTokenConverterInterface
     */
    private $accessTokenConverter;
    /**
     * @var RendererInterface
     */
    private $renderer;

    /**
     * @param AccessTokenConverterInterface $accessTokenConverter
     * @param RendererInterface             $renderer
     */
    public function __construct(
        AccessTokenConverterInterface $accessTokenConverter,
        RendererInterface $renderer
    ) {
        $this->accessTokenConverter = $accessTokenConverter;
        $this->renderer = $renderer;
    }

    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     *
     * @return ResponseTypeInterface
     */
    public function newAccessTokenResponse(AccessTokenEntityInterface $accessTokenEntity)
    {
        return new BearerTokenResponse(
            $this->accessTokenConverter,
            $accessTokenEntity
        );
    }

    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     * @param EncryptedRefreshToken      $encryptedRefreshToken
     *
     * @return ResponseTypeInterface
     */
    public function newRefreshTokenResponse(
        AccessTokenEntityInterface $accessTokenEntity,
        EncryptedRefreshToken $encryptedRefreshToken
    ) {
        return new BearerTokenResponse(
            $this->accessTokenConverter,
            $accessTokenEntity,
            $encryptedRefreshToken
        );
    }

    /**
     * @param AccessTokenEntityInterface $accessTokenEntity
     * @param string                     $redirectUri
     * @param string                     $state
     *
     * @return ResponseTypeInterface
     */
    public function newAccessTokenRedirectResponse(AccessTokenEntityInterface $accessTokenEntity, $redirectUri, $state)
    {
        return new BearerRedirectResponse(
            $this->accessTokenConverter,
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
     * @param LoginData $loginData
     *
     * @return ResponseTypeInterface
     */
    public function newHtmlLoginResponse(LoginData $loginData)
    {
        return new HtmlResponse(
            $this->renderer->renderLogin([
                'error'        => $loginData->getError(),
                'postback_uri' => $this->makeRedirectUri(
                    $loginData->getPostbackUri(),
                    $loginData->getQueryParams()
                ),
            ]),
            403
        );
    }

    /**
     * @param AuthorizeData $authorizeData
     *
     * @return ResponseTypeInterface
     */
    public function newHtmlAuthorizeResponse(AuthorizeData $authorizeData)
    {
        $html = $this->renderer->renderAuthorize([
            'client'       => $authorizeData->getClient(),
            'scopes'       => $authorizeData->getScopes(),
            'postback_uri' => $this->makeRedirectUri(
                $authorizeData->getPostbackUri(),
                $authorizeData->getQueryParams()
            ),
        ]);

        return new HtmlResponse($html, 200, [
            'set-cookie' => sprintf(
                'oauth_authorize_request=%s; Expires=%s',
                urlencode($authorizeData->getEncryptedUserId()),
                (new \DateTime())->add(new \DateInterval('PT5M'))->format('D, d M Y H:i:s e')
            ),
        ]);
    }

    /**
     * @param CodeData $authCodeData
     *
     * @return ResponseTypeInterface
     */
    public function newAuthCodeRedirectResponse(CodeData $authCodeData)
    {
        $state = $authCodeData->getState();

        $redirectPayload = [];
        if ($state !== null) {
            $redirectPayload['state'] = $state;
        }

        $redirectPayload['code'] = $authCodeData->getCode();

        return new RedirectResponse(
            $this->makeRedirectUri(
                $authCodeData->getRedirectUri(),
                $redirectPayload
            )
        );
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
