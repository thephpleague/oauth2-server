<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Exception;

use Psr\Http\Message\ResponseInterface;

class ExceptionResponseHandler implements ExceptionResponseHandlerInterface
{
    /**
     * Generate a HTTP response from am OAuthServerException
     *
     * @param OAuthServerException  $exception
     * @param ResponseInterface     $response
     * @param bool                  $useFragment True if errors should be in the URI fragment instead of query string
     * @param int                   $jsonOptions options passed to json_encode
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(
        OAuthServerException $exception,
        ResponseInterface $response,
        $useFragment = false,
        $jsonOptions = 0
    ) {
        $headers = $exception->getHttpHeaders();

        $payload = $exception->getPayload();

        $redirectUri = $exception->getRedirectUri();
        if ($redirectUri !== null) {
            return $this->generateRedirectResponse($redirectUri, $response, $payload, $useFragment);
        }

        foreach ($headers as $header => $content) {
            $response = $response->withHeader($header, $content);
        }

        $responseBody = \json_encode($payload, $jsonOptions) ?: 'JSON encoding of payload failed';

        $response->getBody()->write($responseBody);

        return $response->withStatus($exception->getHttpStatusCode());
    }

    /**
     * Generate a HTTP response from am OAuthServerException
     *
     * @param string            $redirectUri
     * @param ResponseInterface $response
     * @param string[]          $payload
     * @param bool              $useFragment
     *
     * @return ResponseInterface
     */
    protected function generateRedirectResponse(
        string $redirectUri,
        ResponseInterface $response,
        $payload,
        $useFragment
    ): ResponseInterface {
        if ($useFragment === true) {
            $querySeparator = '#';
        } else {
            $querySeparator = '?';
        }
        $redirectUri .= (\strstr($redirectUri, '?') === false) ? $querySeparator : '&';

        return $response->withStatus(302)->withHeader('Location', $redirectUri . \http_build_query($payload));
    }
}
