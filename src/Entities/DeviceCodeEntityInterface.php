<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

interface DeviceCodeEntityInterface extends TokenInterface
{
    /**
     * @return string
     */
    public function getUserCode();

    /**
     * @param string $userCode
     */
    public function setUserCode($userCode);

    /**
     * @return string
     */
    public function getVerificationUri();

    /**
     * @param string $verificationUri
     */
    public function setVerificationUri($verificationUri);
}
