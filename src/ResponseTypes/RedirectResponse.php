<?php
/**
 * OAuth 2.0 Redirect Response.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use Psr\Http\Message\ResponseInterface;

class RedirectResponse extends AbstractResponseType
{
    /**
     * @var string
     */
    private $redirectUri;

    /**
     * @param string $redirectUri
     */
    public function setRedirectUri($redirectUri)
    {
        $this->redirectUri = $redirectUri;
    }

    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        return $response->withStatus(302)->withHeader('Location', $this->redirectUri);
    }

    /**
     * Generate a string token from the access token
     *
     * @param AccessTokenEntityInterface $accessToken
     *
     * @return string
     */
    public function convert(AccessTokenEntityInterface $accessToken)
    {
        throw new \LogicException('RedirectResponse cannot convert AccessToken');
    }
}
