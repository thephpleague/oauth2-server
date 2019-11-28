<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities\Traits;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

trait DeviceCodeTrait
{
    /**
     * @var string
     */
    private $userCode;

    /**
     * @var string
     */
    private $verificationUri;

    /**
     * @return string
     */
    public function getUserCode()
    {
        return $this->userCode;
    }

    /**
     * @param string $userCode
     *
     * @return string
     */
    public function setUserCode($userCode)
    {
        $this->userCode = $userCode;
    }

    /**
     * @return string
     */
    public function getVerificationUri()
    {
        return $this->verificationUri;
    }

    /**
     * @param string $verificationUri
     */
    public function setVerificationUri($verificationUri)
    {
        $this->verificationUri = $verificationUri;
    }

    /**
     * @return ClientEntityInterface
     */
    abstract public function getClient();

    /**
     * @return DateTimeImmutable
     */
    abstract public function getExpiryDateTime();

    /**
     * @return ScopeEntityInterface[]
     */
    abstract public function getScopes();

    /**
     * @return string
     */
    abstract public function getIdentifier();
}
