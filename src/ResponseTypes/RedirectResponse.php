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

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes;

use Psr\Http\Message\ResponseInterface;

class RedirectResponse extends AbstractResponseType
{
    private string $redirectUri;

    public function setRedirectUri(string $redirectUri): void
    {
        $this->redirectUri = $redirectUri;
    }

    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        return $response->withStatus(302)->withHeader('Location', $this->redirectUri);
    }
}
