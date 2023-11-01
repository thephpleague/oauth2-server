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

namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;

use function time;

class DeviceCodeResponse extends AbstractResponseType
{
    protected DeviceCodeEntityInterface $deviceCode;
    protected string $payload;

    /**
     * {@inheritdoc}
     */
    public function generateHttpResponse(ResponseInterface $response): ResponseInterface 
    {
        $expireDateTime = $this->deviceCode->getExpiryDateTime()->getTimestamp();

        $responseParams = [
            'device_code' => $this->payload,
            'user_code' => $this->deviceCode->getUserCode(),
            'verification_uri' => $this->deviceCode->getVerificationUri(),
            'expires_in'   => $expireDateTime - time(),
            // TODO: Potentially add in verification_uri_complete - it is optional
        ];

        if ($this->deviceCode->getIntervalInAuthResponse() === true) {
            $responseParams['interval'] = $this->deviceCode->getInterval();
        }

        $responseParams = \json_encode($responseParams);

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

    public function setPayload($payload)
    {
        $this->payload = $payload;
    }

    /**
     * {@inheritdoc}
     */
    public function setDeviceCode(DeviceCodeEntityInterface $deviceCode)
    {
        $this->deviceCode = $deviceCode;
    }

    /**
     * Add custom fields to your Bearer Token response here, then override
     * AuthorizationServer::getResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @param DeviceCodeEntityInterface $deviceCode
     *
     * @return array
     */
    protected function getExtraParams(DeviceCodeEntityInterface $deviceCode)
    {
        return [];
    }
}
