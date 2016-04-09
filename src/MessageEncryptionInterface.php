<?php

namespace League\OAuth2\Server;

interface MessageEncryptionInterface
{
    /**
     * Encrypt data.
     *
     * @param string $unencryptedData
     *
     * @return string
     */
    public function encrypt($unencryptedData);

    /**
     * Decrypt data.
     *
     * @param string $encryptedData
     *
     * @throws \LogicException
     *
     * @return string
     */
    public function decrypt($encryptedData);
}
