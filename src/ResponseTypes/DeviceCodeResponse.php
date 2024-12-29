<?php

/**
 * OAuth 2.0 Bearer Token Response.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;

use function json_encode;
use function time;

class DeviceCodeResponse extends AbstractResponseType
{
    protected DeviceCodeEntityInterface $deviceCodeEntity;
    private bool $includeVerificationUriComplete = false;
    private bool $includeInterval = false;

    /**
     * {@inheritdoc}
     */
    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        $expireDateTime = $this->deviceCodeEntity->getExpiryDateTime()->getTimestamp();

        $responseParams = [
            'device_code'      => $this->deviceCodeEntity->getIdentifier(),
            'user_code'        => $this->deviceCodeEntity->getUserCode(),
            'verification_uri' => $this->deviceCodeEntity->getVerificationUri(),
            'expires_in'       => $expireDateTime - time(),
        ];

        if ($this->includeVerificationUriComplete === true) {
            $responseParams['verification_uri_complete'] = $this->deviceCodeEntity->getVerificationUriComplete();
        }

        if ($this->includeInterval === true) {
            $responseParams['interval'] = $this->deviceCodeEntity->getInterval();
        }

        $responseParams = json_encode($responseParams);

        if ($responseParams === false) {
            throw new LogicException('Error encountered JSON encoding response parameters');
        }

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write($responseParams);

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function setDeviceCodeEntity(DeviceCodeEntityInterface $deviceCodeEntity): void
    {
        $this->deviceCodeEntity = $deviceCodeEntity;
    }

    public function includeVerificationUriComplete(): void
    {
        $this->includeVerificationUriComplete = true;
    }

    public function includeInterval(): void
    {
        $this->includeInterval = true;
    }

    /**
     * Add custom fields to your Bearer Token response here, then override
     * AuthorizationServer::getResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @return array<array-key,mixed>
     */
    protected function getExtraParams(DeviceCodeEntityInterface $deviceCode): array
    {
        return [];
    }
}
